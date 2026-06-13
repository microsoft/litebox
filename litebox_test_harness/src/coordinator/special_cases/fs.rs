// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Filesystem and pipe-lifecycle special-case argv leaves, and CWF.*
//! (cross-worker file I/O) tests.

// TODO(#15): convert legacy wildcard enum dispatch in this file to explicit arms.
#![allow(clippy::wildcard_enum_match_arm)]

use super::*;

use crate::handlers::{HandlerCtx, HandlerError, HandlerToken};
use serde::{Deserialize, Serialize};
use std::process::{Command as StdCommand, Stdio};

#[derive(Serialize, Deserialize)]
pub(super) struct LeafArgs {
    pub sub: String,
    pub extra: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct LeafOut {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

use std::io::Write;

pub fn run(sub: &str, args: &[String]) -> i32 {
    match sub {
        "io" => {
            let op = args.get(3).map_or("write-read", String::as_str);
            let path = args.get(4).map_or("/tmp/fs-test.txt", String::as_str);
            test_io(op, path)
        }
        "exec-write" => {
            let bin_type = args.get(3).map_or("pie", String::as_str);
            let path = args.get(4).map_or("/tmp/fs-exec.txt", String::as_str);
            test_exec_write(bin_type, path)
        }
        // fs-test exec-open-read <binary-type> <path>
        // Fork+exec child that writes AND keeps fd open; parent reads while child alive.
        "exec-open-read" => {
            let bin_type = args.get(3).map_or("pie", String::as_str);
            let path = args.get(4).map_or("/tmp/fs-open.txt", String::as_str);
            test_exec_open_read(bin_type, path)
        }
        // Diagnostic: pinpoint where exec-open-read hangs
        // Helper: write to file then sleep (keeps process alive with file written)
        "do-write-sleep" => {
            let path = args.get(3).map_or("/tmp/fs-open.txt", String::as_str);
            let data = args.get(4).map_or("OPEN_WRITE_DATA", String::as_str);
            std::fs::write(path, data.as_bytes()).unwrap_or_else(|e| {
                eprintln!("do-write-sleep: write failed: {e}");
                std::process::exit(1);
            });
            // Keep alive so the parent can read while we're still running
            std::thread::sleep(std::time::Duration::from_secs(30));
            0
        }
        // Called by exec-write to actually write the file
        "do-write" => {
            let path = args.get(3).map_or("/tmp/fs-exec.txt", String::as_str);
            let data = args.get(4).map_or("EXEC_WRITE_DATA", String::as_str);
            match std::fs::write(path, data.as_bytes()) {
                Ok(()) => 0,
                Err(e) => {
                    eprintln!("do-write: {e}");
                    1
                }
            }
        }
        _ => {
            eprintln!("fs-test subcommands: io, exec-write, do-write");
            1
        }
    }
}

/// Fork+exec a binary to write a file, then read it from the parent.
fn test_exec_write(bin_type: &str, path: &str) -> i32 {
    let _ = std::fs::remove_file(path);
    let self_exe = std::env::current_exe().unwrap();
    let self_exe = self_exe.to_str().unwrap();
    let data = "EXEC_WRITE_OK";

    let child = match bin_type {
        "pie" => std::process::Command::new(self_exe)
            .args(["fs-test", "do-write", path, data])
            .output(),
        "nonpie" => {
            let bin = crate::nonpie_binary();
            std::process::Command::new(&bin)
                .args(["fs-test", "do-write", path, data])
                .output()
        }
        other => {
            println!("FS_ERR:op=exec-write,unknown_bin_type={other}");
            return 1;
        }
    };

    match child {
        Ok(out) if !out.status.success() => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            println!(
                "FS_ERR:op=exec-write,bin={bin_type},path={path},exit={},err={}",
                out.status.code().unwrap_or(-1),
                stderr.lines().next().unwrap_or("")
            );
            return 1;
        }
        Err(e) => {
            println!("FS_ERR:op=exec-write,bin={bin_type},path={path},spawn_err={e}");
            return 1;
        }
        _ => {}
    }

    match std::fs::read_to_string(path) {
        Ok(s) if s == data => {
            println!("FS_OK:op=exec-write,bin={bin_type},path={path}");
            0
        }
        Ok(s) => {
            println!(
                "FS_ERR:op=exec-write,bin={bin_type},path={path},got={}",
                s.escape_default()
            );
            1
        }
        Err(e) => {
            println!("FS_ERR:op=exec-write,bin={bin_type},path={path},read_err={e}");
            1
        }
    }
}

/// Fork+exec child that writes AND keeps running; parent reads while child alive.
/// This is the exact pre-warm pattern — tests 9P coherence for open files on remote workers.
fn test_exec_open_read(bin_type: &str, path: &str) -> i32 {
    let _ = std::fs::remove_file(path);
    let self_exe = std::env::current_exe().unwrap();
    let self_exe = self_exe.to_str().unwrap();
    let data = "OPEN_READ_DATA";

    let bin = match bin_type {
        "pie" => self_exe.to_string(),
        "nonpie" => crate::nonpie_binary(),
        other => {
            println!("FS_ERR:op=exec-open-read,unknown_bin_type={other}");
            return 1;
        }
    };

    // Spawn child that writes then sleeps (keeps process alive).
    // Use null stdout/stderr so the child doesn't hold the parent's
    // piped stdout open (which would prevent the agent from reading EOF).
    let mut child = match std::process::Command::new(&bin)
        .args(["fs-test", "do-write-sleep", path, data])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            println!("FS_ERR:op=exec-open-read,bin={bin_type},path={path},spawn_err={e}");
            return 1;
        }
    };

    // Wait for the child to create the file, then read while it is still alive.
    // Cross-binary-type exec can spend several seconds starting the new worker
    // before the leaf reaches do-write-sleep.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    let mut result;
    loop {
        result = std::fs::read_to_string(path);
        if result.is_ok() || std::time::Instant::now() >= deadline {
            break;
        }
        if matches!(child.try_wait(), Ok(Some(_))) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    match &result {
        Ok(s) if s == data => {
            println!("FS_OK:op=exec-open-read,bin={bin_type},path={path}");
        }
        Ok(s) => {
            println!(
                "FS_ERR:op=exec-open-read,bin={bin_type},path={path},got={}",
                s.escape_default()
            );
        }
        Err(e) => {
            println!("FS_ERR:op=exec-open-read,bin={bin_type},path={path},read_err={e}");
        }
    }

    // Clean up — kill may hang on wait, so don't block on it
    let _ = child.kill();
    // Don't call child.wait() — it can hang in litebox
    result.map_or(1, |s| i32::from(s != data))
}

#[allow(clippy::too_many_lines)] // exhaustive runner / dispatch table
fn test_io(op: &str, path: &str) -> i32 {
    let _ = std::fs::remove_file(path);
    match op {
        // FS1: Simple write then read (same process, sequential)
        "write-read" => {
            std::fs::write(path, b"FS_DATA_42").unwrap_or_else(|e| {
                println!("FS_ERR:op={op},path={path},phase=write,err={e}");
                std::process::exit(1);
            });
            match std::fs::read_to_string(path) {
                Ok(s) if s == "FS_DATA_42" => {
                    println!("FS_OK:op={op},path={path}");
                    0
                }
                Ok(s) => {
                    println!("FS_ERR:op={op},path={path},phase=read,got={s}");
                    1
                }
                Err(e) => {
                    println!("FS_ERR:op={op},path={path},phase=read,err={e}");
                    1
                }
            }
        }
        // FS2: Append then read
        "append-read" => {
            std::fs::write(path, b"LINE1\n").unwrap_or_else(|e| {
                println!("FS_ERR:op={op},path={path},phase=write1,err={e}");
                std::process::exit(1);
            });
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(path)
                .unwrap_or_else(|e| {
                    println!("FS_ERR:op={op},path={path},phase=open-append,err={e}");
                    std::process::exit(1);
                });
            f.write_all(b"LINE2\n").unwrap();
            drop(f);
            match std::fs::read_to_string(path) {
                Ok(s) if s == "LINE1\nLINE2\n" => {
                    println!("FS_OK:op={op},path={path}");
                    0
                }
                Ok(s) => {
                    println!(
                        "FS_ERR:op={op},path={path},phase=read,got={}",
                        s.escape_default()
                    );
                    1
                }
                Err(e) => {
                    println!("FS_ERR:op={op},path={path},phase=read,err={e}");
                    1
                }
            }
        }
        // FS3: Write in background thread, read from main thread (concurrent)
        "write-bg-read" => {
            let p = path.to_string();
            let handle = std::thread::spawn(move || {
                let mut f = std::fs::File::create(&p).unwrap();
                f.write_all(b"BG_DATA").unwrap();
                f.sync_all().unwrap();
            });
            handle.join().unwrap();
            // Writer is done and joined — file should be readable
            match std::fs::read_to_string(path) {
                Ok(s) if s == "BG_DATA" => {
                    println!("FS_OK:op={op},path={path}");
                    0
                }
                Ok(s) => {
                    println!("FS_ERR:op={op},path={path},phase=read,got={s}");
                    1
                }
                Err(e) => {
                    println!("FS_ERR:op={op},path={path},phase=read,err={e}");
                    1
                }
            }
        }
        // FS4: Shell redirect (like code-server pre-warm) — background write, foreground read
        // This is the exact pattern: `cmd > file &` then `cat file`
        "redirect-bg-read" => {
            let p = path.to_string();
            // Write via a child process with stdout redirected to file
            let child = std::process::Command::new("/usr/bin/bash")
                .args(["-c", &format!("echo REDIRECT_DATA > {p}")])
                .output();
            match child {
                Ok(out) if out.status.success() => {}
                Ok(out) => {
                    println!(
                        "FS_ERR:op={op},path={path},phase=write,exit={}",
                        out.status.code().unwrap_or(-1)
                    );
                    return 1;
                }
                Err(e) => {
                    println!("FS_ERR:op={op},path={path},phase=spawn,err={e}");
                    return 1;
                }
            }
            match std::fs::read_to_string(path) {
                Ok(s) if s.trim() == "REDIRECT_DATA" => {
                    println!("FS_OK:op={op},path={path}");
                    0
                }
                Ok(s) => {
                    println!(
                        "FS_ERR:op={op},path={path},phase=read,got={}",
                        s.escape_default()
                    );
                    1
                }
                Err(e) => {
                    println!("FS_ERR:op={op},path={path},phase=read,err={e}");
                    1
                }
            }
        }
        // FS5: Fork child writes, parent reads (cross-process, still open fd)
        "fork-write-read" => {
            let pid = unsafe { libc::fork() };
            if pid < 0 {
                println!("FS_ERR:op={op},path={path},phase=fork");
                return 1;
            }
            if pid == 0 {
                // Child: write to file and exit
                match std::fs::write(path, b"FORK_DATA") {
                    Ok(()) => std::process::exit(0),
                    Err(_) => std::process::exit(1),
                }
            }
            // Parent: wait for child, then read
            let mut status: i32 = 0;
            unsafe { libc::waitpid(pid, &raw mut status, 0) };
            match std::fs::read_to_string(path) {
                Ok(s) if s == "FORK_DATA" => {
                    println!("FS_OK:op={op},path={path}");
                    0
                }
                Ok(s) => {
                    println!("FS_ERR:op={op},path={path},phase=read,got={s}");
                    1
                }
                Err(e) => {
                    println!("FS_ERR:op={op},path={path},phase=read,err={e}");
                    1
                }
            }
        }
        // FS6: Background process writes to file via redirect, WHILE file is still open,
        // another process reads. This is the exact code-server pre-warm pattern.
        "bg-open-read" => {
            let p = path.to_string();
            // Start a background writer that keeps the file open.
            // Intentionally never wait()ed — wait can hang under
            // litebox; we kill() before returning.
            #[allow(clippy::zombie_processes)]
            let mut child = std::process::Command::new("/usr/bin/bash")
                .args([
                    "-c",
                    &format!("echo LINE1 > {p}; sleep 1; echo LINE2 >> {p}; sleep 5"),
                ])
                .spawn()
                .unwrap_or_else(|e| {
                    println!("FS_ERR:op={op},path={path},phase=spawn,err={e}");
                    std::process::exit(1);
                });

            // Wait for first line to be written
            std::thread::sleep(std::time::Duration::from_millis(500));

            // Try to read while writer still has file open
            let result = std::fs::read_to_string(path);

            // Print result BEFORE kill/wait (wait can hang in litebox)
            let rc = match &result {
                Ok(s) if s.contains("LINE1") => {
                    println!(
                        "FS_OK:op={op},path={path},content={}",
                        s.trim().escape_default()
                    );
                    0
                }
                Ok(s) => {
                    println!(
                        "FS_ERR:op={op},path={path},phase=read,got={}",
                        s.escape_default()
                    );
                    1
                }
                Err(e) => {
                    println!("FS_ERR:op={op},path={path},phase=read,err={e}");
                    1
                }
            };

            let _ = child.kill();
            rc
        }
        // FS7: Parent opens file for writing, forks, child writes via inherited fd,
        // parent reads. This is the pre-warm pattern: bash opens log.txt with >,
        // backgrounds code-server (fork), child writes to inherited stdout=log.txt,
        // later the CLI reads log.txt.
        "parent-open-fork-read" => {
            let f = std::fs::File::create(path).unwrap_or_else(|e| {
                println!("FS_ERR:op={op},path={path},phase=create,err={e}");
                std::process::exit(1);
            });
            let fd = {
                use std::os::unix::io::AsRawFd;
                f.as_raw_fd()
            };

            let pid = unsafe { libc::fork() };
            if pid < 0 {
                println!("FS_ERR:op={op},path={path},phase=fork");
                return 1;
            }
            if pid == 0 {
                // Child: write to inherited fd, then sleep (keep fd open)
                let msg = b"CHILD_WROTE_THIS\n";
                unsafe { libc::write(fd, msg.as_ptr().cast(), msg.len()) };
                std::thread::sleep(std::time::Duration::from_secs(5));
                std::process::exit(0);
            }

            // Parent: close our copy of the write fd, wait a bit, then read
            drop(f);
            std::thread::sleep(std::time::Duration::from_millis(500));

            let result = std::fs::read_to_string(path);
            unsafe {
                libc::kill(pid, libc::SIGKILL);
                libc::waitpid(pid, std::ptr::null_mut(), 0);
            }
            match result {
                Ok(s) if s.contains("CHILD_WROTE_THIS") => {
                    println!("FS_OK:op={op},path={path}");
                    0
                }
                Ok(s) => {
                    println!(
                        "FS_ERR:op={op},path={path},phase=read,got={}",
                        s.escape_default()
                    );
                    1
                }
                Err(e) => {
                    println!("FS_ERR:op={op},path={path},phase=read,err={e}");
                    1
                }
            }
        }
        other => {
            println!("FS_ERR:unknown_op={other}");
            1
        }
    }
}

#[allow(dead_code)]
pub(super) const RUN: HandlerToken<LeafArgs, LeafOut> = HandlerToken::new("special_cases.fs.run");

#[allow(dead_code)]
pub(super) async fn handle_run(
    args: LeafArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<LeafOut, HandlerError> {
    let output = StdCommand::new(std::env::current_exe()?)
        .arg("fs-test")
        .arg(args.sub)
        .args(args.extra)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
    Ok(LeafOut {
        exit_code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    })
}

/// Register argv leaves used by exec-driven filesystem/pipe-lifecycle tests.
pub(super) fn register() {
    crate::register_handler!(RUN, handle_run);
    crate::register_leaf_subcommand!("fs-test", subcmd_fs_test);
}

fn subcmd_fs_test(args: &[String]) -> i32 {
    run(args.get(2).map_or("help", String::as_str), args)
}

/// Register FS I/O matrix tests.
pub(super) fn register_fs_io(reg: &mut Registry<'_>) {
    register();
    let ops: &[&str] = &[
        "write-read",
        "append-read",
        "write-bg-read",
        "redirect-bg-read",
        "fork-write-read",
        "bg-open-read",
        "parent-open-fork-read",
    ];
    let paths: &[(&str, &str)] = &[("/tmp/fs-test.txt", "tmp"), ("/root/fs-test.txt", "root")];

    for &op in ops {
        for &(path, dir) in paths {
            for &bt in crate::BinaryType::ALL {
                let id = format!("FS.{op}.{dir}.{}", bt.label());
                let op = op.to_string();
                let path = path.to_string();
                typed_test!(
                    reg,
                    "matrix",
                    "fs_io",
                    id,
                    timeout = 60,
                    agents[a = AgentName::Dpg1],
                    |run| {
                        let self_exe = run.self_exe().to_string();
                        let target = crate::binary_path(bt, &self_exe);
                        let resp = run
                            .send_named_typed(
                                &a,
                                &EXEC_BIN,
                                ExecBinArgs {
                                    argv: vec![target, "fs-test".into(), "io".into(), op, path],
                                    timeout_ms: Some(15 * 1000),
                                    stdin: None,
                                    env: vec![],
                                },
                            )
                            .await;
                        let pass = matches!(&resp, Ok(out) if out.stdout.contains("FS_OK"));
                        crate::coordinator::TestOutcome::new("A", pass, format!("{resp:?}"))
                    }
                );
            }
        }
    }

    for &mode in &["exec-write", "exec-open-read"] {
        let prefix = if mode == "exec-write" { "exec" } else { "open" };
        for &bin in &["pie", "nonpie"] {
            for &bt in crate::BinaryType::ALL {
                let path = "/tmp/fs-exec.txt";
                let pname = "fs-exec.txt";
                let id = format!("FS.{prefix}_{bin}_{pname}.{}", bt.label());
                let mode = mode.to_string();
                let bin = bin.to_string();
                let path = path.to_string();
                typed_test!(
                    reg,
                    "matrix",
                    "fs_io",
                    id,
                    timeout = 60,
                    agents[a = AgentName::Dpg1],
                    |run| {
                        let self_exe = run.self_exe().to_string();
                        let target = crate::binary_path(bt, &self_exe);
                        let resp = run
                            .send_named_typed(
                                &a,
                                &EXEC_BIN,
                                ExecBinArgs {
                                    argv: vec![target, "fs-test".into(), mode, bin, path],
                                    timeout_ms: Some(30 * 1000),
                                    stdin: None,
                                    env: vec![],
                                },
                            )
                            .await;
                        let pass = matches!(&resp, Ok(out) if out.stdout.contains("FS_OK"));
                        crate::coordinator::TestOutcome::new("A", pass, format!("{resp:?}"))
                    }
                );
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// CWF: cross-worker file I/O
// ═══════════════════════════════════════════════════════════════════

/// Agents exercised by cross-worker-file tests.
const CWF_AGENTS: &[AgentName] = &[AgentName::Dpg1, AgentName::Dpg1Dpg1, AgentName::Dpg2];

#[derive(Serialize, Deserialize, Debug)]
struct CrossWorkerFileArgs {
    mode: String,
    path: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct CwfOut {
    detail: String,
}

const CROSS_WORKER_FILE: HandlerToken<CrossWorkerFileArgs, CwfOut> =
    HandlerToken::new("platform_fixes.cross_worker_file");

async fn handle_cross_worker_file(
    args: CrossWorkerFileArgs,
    ctx: &mut HandlerCtx<'_>,
) -> Result<CwfOut, HandlerError> {
    use std::io::Write;
    let keep_open = args.mode == "write-and-hold";
    let checkpoint = keep_open || args.mode == "write-and-sleep";
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&args.path)
        .map_err(|e| HandlerError::from(format!("open {}: {e}", args.path)))?;
    for i in 0..5 {
        writeln!(f, "line{i}").map_err(|e| HandlerError::from(format!("write: {e}")))?;
    }
    f.flush()
        .map_err(|e| HandlerError::from(format!("flush: {e}")))?;
    if !keep_open {
        drop(f);
    }
    if checkpoint {
        ctx.checkpoint("cross-worker-file-ready").await?;
    }
    Ok(CwfOut {
        detail: "[cross-worker-file] READY".into(),
    })
}

/// Argv-dispatched leaf: writes lines to a file, optionally holding the fd open.
///
/// Lives as a leaf subcommand because the `CWF.redirect_stdout` variant spawns
/// the binary via `bash -c "{exe} cross-worker-file write-stdout > {path} &"`,
/// where stdout must be the write-fd rather than the agent protocol pipe.
fn subcmd_cross_worker_file(args: &[String]) -> i32 {
    use std::io::Write;
    let sub = args.get(2).map_or("", String::as_str);
    if sub == "write-and-sleep" || sub == "write-and-exit" || sub == "write-and-hold" {
        let path = args.get(3).map_or("/tmp/cwf.log", String::as_str);
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .unwrap();
        for i in 0..5 {
            writeln!(f, "line{i}").unwrap();
        }
        f.flush().unwrap();
        eprintln!("[cross-worker-file] READY");
        if sub == "write-and-hold" {
            std::thread::sleep(std::time::Duration::from_secs(10));
            drop(f);
        } else {
            drop(f);
            if sub == "write-and-sleep" {
                std::thread::sleep(std::time::Duration::from_secs(10));
            }
        }
        return 0;
    }
    if sub == "write-stdout" {
        for i in 0..5 {
            println!("line{i}");
        }
        std::io::stdout().flush().unwrap();
        eprintln!("[cross-worker-file] READY");
        std::thread::sleep(std::time::Duration::from_secs(10));
        return 0;
    }
    1
}

fn register_cwf_handlers() {
    crate::register_handler!(CROSS_WORKER_FILE, handle_cross_worker_file);
    crate::register_leaf_subcommand!("cross-worker-file", subcmd_cross_worker_file);
}

/// Register CWF.* (cross-worker file I/O) tests.
#[allow(clippy::too_many_lines)]
pub(super) fn register_cross_worker_file_tests(reg: &mut Registry<'_>) {
    use super::super::matrix::{
        EXEC, EXEC_READY, ExecArgs, ExecReadyArgs, FS_DELETE, FS_READ, FsPathArgs, KILL, KillArgs,
    };
    register_cwf_handlers();
    for &agent in CWF_AGENTS {
        let agent_s = agent.to_string();

        // CWF.seq: child writes, exits, parent reads.
        {
            let a = agent_s.clone();
            reg.test("xworker", "cross_worker_file", format!("CWF.seq.{agent}"))
                .timeout(60)
                .build(move |cx| {
                    let handle = cx.require(agent);
                    let leaf = cx.declare_ephemeral(
                        agent,
                        format!("CrossWorkerFileSeq_{agent}"),
                        SpawnKind::Fork {
                            binary: "self",
                            inherit_listen_ports: vec![],
                        },
                    );
                    Box::new(move |run| {
                        let a = a.clone();
                        Box::pin(async move {
                            let path = format!("/shared/cwf-seq-{a}.txt");
                            let result = run
                                .run_leaf(
                                    &leaf,
                                    &CROSS_WORKER_FILE,
                                    CrossWorkerFileArgs {
                                        mode: "write-and-exit".into(),
                                        path: path.clone(),
                                    },
                                )
                                .await;
                            if let Err(e) = result {
                                return crate::coordinator::TestOutcome::new(&a, false, e);
                            }
                            let resp = run
                                .typed_or_error(
                                    &handle,
                                    &FS_READ,
                                    FsPathArgs { path: path.clone() },
                                )
                                .await;
                            let pass = matches!(
                                &resp,
                                Response::Ok { data: Some(d) } if d.starts_with("line0")
                            );
                            crate::coordinator::TestOutcome::new(&a, pass, format!("{resp:?}"))
                        })
                    })
                });
        }

        // CWF.concurrent: child writes, closes fd, stays alive, parent reads.
        {
            let a = agent_s.clone();
            reg.test(
                "xworker",
                "cross_worker_file",
                format!("CWF.concurrent.{agent}"),
            )
            .timeout(60)
            .build(move |cx| {
                let handle = cx.require(agent);
                let leaf = cx.declare_ephemeral(
                    agent,
                    format!("CrossWorkerFileConcurrent_{agent}"),
                    SpawnKind::Fork {
                        binary: "self",
                        inherit_listen_ports: vec![],
                    },
                );
                Box::new(move |run| {
                    let a = a.clone();
                    Box::pin(async move {
                        let path = format!("/shared/cwf-conc-{a}.txt");
                        if let Err(e) = run
                            .run_leaf_write(
                                &leaf,
                                &CROSS_WORKER_FILE,
                                CrossWorkerFileArgs {
                                    mode: "write-and-sleep".into(),
                                    path: path.clone(),
                                },
                            )
                            .await
                        {
                            return crate::coordinator::TestOutcome::new(&a, false, e);
                        }
                        if let Err(e) = run
                            .run_leaf_read_checkpoint(&leaf, "cross-worker-file-ready")
                            .await
                        {
                            return crate::coordinator::TestOutcome::new(&a, false, e);
                        }
                        let resp = run
                            .typed_or_error(&handle, &FS_READ, FsPathArgs { path: path.clone() })
                            .await;
                        let pass = matches!(
                            &resp,
                            Response::Ok { data: Some(d) } if d.starts_with("line0")
                        );
                        let _ = run.run_leaf_resume(&leaf, "cross-worker-file-ready").await;
                        let _ = run.run_leaf_read_result(&leaf, &CROSS_WORKER_FILE).await;
                        let _ = run.run_leaf_exit(&leaf).await;
                        crate::coordinator::TestOutcome::new(&a, pass, format!("{resp:?}"))
                    })
                })
            });
        }

        // CWF.hold: child writes, keeps fd OPEN, parent reads.
        {
            let a = agent_s.clone();
            reg.test("xworker", "cross_worker_file", format!("CWF.hold.{agent}"))
                .timeout(60)
                .build(move |cx| {
                    let handle = cx.require(agent);
                    let leaf = cx.declare_ephemeral(
                        agent,
                        format!("CrossWorkerFileHold_{agent}"),
                        SpawnKind::Fork {
                            binary: "self",
                            inherit_listen_ports: vec![],
                        },
                    );
                    Box::new(move |run| {
                        let a = a.clone();
                        Box::pin(async move {
                            let path = format!("/shared/cwf-hold-{a}.txt");
                            let started = run
                                .run_leaf_write(
                                    &leaf,
                                    &CROSS_WORKER_FILE,
                                    CrossWorkerFileArgs {
                                        mode: "write-and-hold".into(),
                                        path: path.clone(),
                                    },
                                )
                                .await;
                            if let Err(e) = started {
                                return crate::coordinator::TestOutcome::new(&a, false, e);
                            }
                            if let Err(e) = run
                                .run_leaf_read_checkpoint(&leaf, "cross-worker-file-ready")
                                .await
                            {
                                return crate::coordinator::TestOutcome::new(&a, false, e);
                            }
                            let resp = run
                                .typed_or_error(
                                    &handle,
                                    &FS_READ,
                                    FsPathArgs { path: path.clone() },
                                )
                                .await;
                            let pass = matches!(
                                &resp,
                                Response::Ok { data: Some(d) } if d.starts_with("line0")
                            );
                            let _ = run.run_leaf_resume(&leaf, "cross-worker-file-ready").await;
                            let _ = run.run_leaf_read_result(&leaf, &CROSS_WORKER_FILE).await;
                            let _ = run.run_leaf_exit(&leaf).await;
                            crate::coordinator::TestOutcome::new(&a, pass, format!("{resp:?}"))
                        })
                    })
                });
        }

        // CWF.full_visibility: child writes 4 distinct lines and KEEPS
        // fd open; parent reads via the FS_READ handler and validates
        // the COMPLETE content (all 4 lines) is visible.
        //
        // This is the strict cross-process visibility test. Failure
        // mode reproduces the VS Code Server `vscode::server_listen`
        // litebox-pass FAIL: a static-PIE-musl writer process
        // (`code-${COMMIT}` in the real scenario) writes its
        // `Listening on N.N.N.N:PORT` line to a redirected stdout,
        // then continues running (doesn't exit, doesn't close fd).
        // A bash subshell from a second SSH session reads the file
        // via `grep` and never sees the `Listening on` line — even
        // 30+ seconds after the writer claims to have written it.
        //
        // Root cause hypothesis: `litebox/src/fs/nine_p/mod.rs`'s
        // write-behind buffer (`write_buffers: BTreeMap<Fid,
        // WriteBuffer>` line 397, `WRITE_BUFFER_CAPACITY = 256 KiB`
        // line 331) is per-litebox-client (= per guest process).
        // The write-behind buffer is flushed only on intra-process
        // events: reads/seeks/opens on the same file (line
        // 1469/1278/1372/1721/1758), sibling-fid writes (line
        // 1598), or close (line 1431). Reads from a DIFFERENT guest
        // process don't see the writer's buffered data because each
        // litebox runner instance has its own buffer map. POSIX
        // requires writes from one process to be immediately visible
        // to reads from another — litebox's write-behind violates
        // that contract.
        //
        // CWF.hold passes today only because it checks
        // `starts_with("line0")` — it would pass even if only the
        // first 6 bytes are visible. This test asserts the COMPLETE
        // 30-byte content.
        for &bt in crate::BinaryType::ALL {
            let bt_label = bt.label();
            let bin_label = crate::coordinator::common::fork_binary_label(bt);
            let a = agent_s.clone();
            reg.test(
                "xworker",
                "cross_worker_file",
                format!("CWF.full_visibility.{bt_label}.{agent}"),
            )
            .timeout(60)
            .build(move |cx| {
                let handle = cx.require(agent);
                let leaf = cx.declare_ephemeral(
                    agent,
                    format!("CrossWorkerFileFullVis_{bt_label}_{agent}"),
                    SpawnKind::Fork {
                        binary: bin_label,
                        inherit_listen_ports: vec![],
                    },
                );
                Box::new(move |run| {
                    let a = a.clone();
                    Box::pin(async move {
                        let path = format!("/shared/cwf-fullvis-{bt_label}-{a}.txt");
                        let _ = run
                            .typed_or_error(&handle, &FS_DELETE, FsPathArgs { path: path.clone() })
                            .await;
                        if let Err(e) = run
                            .run_leaf_write(
                                &leaf,
                                &CROSS_WORKER_FILE,
                                CrossWorkerFileArgs {
                                    mode: "write-and-hold".into(),
                                    path: path.clone(),
                                },
                            )
                            .await
                        {
                            return crate::coordinator::TestOutcome::new(&a, false, e);
                        }
                        if let Err(e) = run
                            .run_leaf_read_checkpoint(&leaf, "cross-worker-file-ready")
                            .await
                        {
                            return crate::coordinator::TestOutcome::new(&a, false, e);
                        }
                        // Writer claims it has written all 5 lines and flushed.
                        // Strict check: reader sees the EXACT expected content.
                        let expected = "line0\nline1\nline2\nline3\nline4\n";
                        let resp = run
                            .typed_or_error(&handle, &FS_READ, FsPathArgs { path: path.clone() })
                            .await;
                        let (pass, detail) = match &resp {
                            Response::Ok { data: Some(d) } if d == expected => {
                                (true, format!("read {} bytes, exact match", d.len()))
                            }
                            Response::Ok { data: Some(d) } => (
                                false,
                                format!(
                                    "INCOMPLETE: writer wrote {} bytes, reader sees {} bytes. \
                                     Expected {:?}, got {:?}",
                                    expected.len(),
                                    d.len(),
                                    expected,
                                    d,
                                ),
                            ),
                            other => (false, format!("read failed: {other:?}")),
                        };
                        let _ = run.run_leaf_resume(&leaf, "cross-worker-file-ready").await;
                        let _ = run.run_leaf_read_result(&leaf, &CROSS_WORKER_FILE).await;
                        let _ = run.run_leaf_exit(&leaf).await;
                        crate::coordinator::TestOutcome::new(&a, pass, detail)
                    })
                })
            });
        }

        // CWF.self_open: child opens file itself (no inherited fd).
        {
            let a = agent_s.clone();
            reg.test(
                "xworker",
                "cross_worker_file",
                format!("CWF.self_open.{agent}"),
            )
            .timeout(60)
            .build(move |cx| {
                let handle = cx.require(agent);
                let leaf = cx.declare_ephemeral(
                    agent,
                    format!("CrossWorkerFileSelfOpen_{agent}"),
                    SpawnKind::Fork {
                        binary: "self",
                        inherit_listen_ports: vec![],
                    },
                );
                Box::new(move |run| {
                    let a = a.clone();
                    Box::pin(async move {
                        let path = format!("/shared/cwf-self-{a}.txt");
                        let _ = run
                            .typed_or_error(&handle, &FS_DELETE, FsPathArgs { path: path.clone() })
                            .await;
                        if let Err(e) = run
                            .run_leaf_write(
                                &leaf,
                                &CROSS_WORKER_FILE,
                                CrossWorkerFileArgs {
                                    mode: "write-and-hold".into(),
                                    path: path.clone(),
                                },
                            )
                            .await
                        {
                            return crate::coordinator::TestOutcome::new(&a, false, e);
                        }
                        if let Err(e) = run
                            .run_leaf_read_checkpoint(&leaf, "cross-worker-file-ready")
                            .await
                        {
                            return crate::coordinator::TestOutcome::new(&a, false, e);
                        }
                        let resp = run
                            .typed_or_error(&handle, &FS_READ, FsPathArgs { path: path.clone() })
                            .await;
                        let pass = matches!(
                            &resp,
                            Response::Ok { data: Some(d) } if d.starts_with("line0")
                        );
                        let _ = run.run_leaf_resume(&leaf, "cross-worker-file-ready").await;
                        let _ = run.run_leaf_read_result(&leaf, &CROSS_WORKER_FILE).await;
                        let _ = run.run_leaf_exit(&leaf).await;
                        crate::coordinator::TestOutcome::new(&a, pass, format!("{resp:?}"))
                    })
                })
            });
        }

        // CWF.redirect_stdout: bash `cmd > file &` pattern.
        {
            let a = agent_s.clone();
            reg.test(
                "xworker",
                "cross_worker_file",
                format!("CWF.redirect_stdout.{agent}"),
            )
            .timeout(60)
            .build(move |cx| {
                let handle = cx.require(agent);
                Box::new(move |run| {
                    let a = a.clone();
                    let self_exe = run.self_exe().to_string();
                    Box::pin(async move {
                        let path = format!("/shared/cwf-rstdout-{a}.txt");
                        let script = format!(
                            concat!(
                                "rm -f {path}; ",
                                "{exe} cross-worker-file write-stdout > {path} &\n",
                                "wait $!\n",
                            ),
                            path = path,
                            exe = self_exe,
                        );
                        let resp = run
                            .typed_or_error(
                                &handle,
                                &EXEC_READY,
                                ExecReadyArgs {
                                    args: vec!["bash".into(), "-c".into(), script],
                                    ready_marker: "[cross-worker-file] READY".into(),
                                    timeout_secs: Some(15),
                                    stdin: None,
                                    stream: "stderr".into(),
                                },
                            )
                            .await;
                        let pid = match &resp {
                            Response::BackgroundReady { pid } => Some(*pid),
                            _ => {
                                return crate::coordinator::TestOutcome::new(
                                    &a,
                                    false,
                                    format!("bg spawn failed: {resp:?}"),
                                );
                            }
                        };
                        let resp = run
                            .typed_or_error(&handle, &FS_READ, FsPathArgs { path: path.clone() })
                            .await;
                        let pass = matches!(
                            &resp,
                            Response::Ok { data: Some(d) } if d.contains("line0")
                        );
                        if let Some(pid) = pid {
                            let _ = run.typed_or_error(&handle, &KILL, KillArgs { pid }).await;
                        }
                        crate::coordinator::TestOutcome::new(&a, pass, format!("{resp:?}"))
                    })
                })
            });
        }

        // CWF.redirect_exit: child exits quickly, data becomes visible.
        {
            let a = agent_s.clone();
            reg.test(
                "xworker",
                "cross_worker_file",
                format!("CWF.redirect_exit.{agent}"),
            )
            .timeout(60)
            .build(move |cx| {
                let handle = cx.require(agent);
                Box::new(move |run| {
                    let a = a.clone();
                    let self_exe = run.self_exe().to_string();
                    Box::pin(async move {
                        let path = format!("/shared/cwf-rexit-{a}.txt");
                        let script = format!(
                            concat!(
                                "rm -f {path}; ",
                                "{exe} echo-test ",
                                "> {path} 2>&1\n",
                                "cat {path}\n",
                            ),
                            path = path,
                            exe = self_exe,
                        );
                        let resp = run
                            .typed_or_error(
                                &handle,
                                &EXEC,
                                ExecArgs {
                                    args: vec!["bash".into(), "-c".into(), script],
                                    timeout_secs: Some(15),
                                    stdin: None,
                                    background: false,
                                    env: vec![],
                                },
                            )
                            .await;
                        let pass = matches!(
                            &resp,
                            Response::ExecResult { stdout, .. }
                                if stdout.contains("ECHO_TEST_OK")
                        );
                        crate::coordinator::TestOutcome::new(&a, pass, format!("{resp:?}"))
                    })
                })
            });
        }

        // CWF.builtin_redirect: shell builtin redirected to file.
        {
            let a = agent_s.clone();
            reg.test(
                "xworker",
                "cross_worker_file",
                format!("CWF.builtin_redirect.{agent}"),
            )
            .timeout(60)
            .build(move |cx| {
                let handle = cx.require(agent);
                Box::new(move |run| {
                    let a = a.clone();
                    Box::pin(async move {
                        let path = format!("/shared/cwf-builtin-{a}.txt");
                        let script = format!(
                            concat!(
                                "rm -f {path}; ",
                                "echo builtin-data > {path}\n",
                                "cat {path}\n",
                            ),
                            path = path,
                        );
                        let resp = run
                            .typed_or_error(
                                &handle,
                                &EXEC,
                                ExecArgs {
                                    args: vec!["bash".into(), "-c".into(), script],
                                    timeout_secs: Some(10),
                                    stdin: None,
                                    background: false,
                                    env: vec![],
                                },
                            )
                            .await;
                        let pass = matches!(
                            &resp,
                            Response::ExecResult { stdout, .. }
                                if stdout.contains("builtin-data")
                        );
                        crate::coordinator::TestOutcome::new(&a, pass, format!("{resp:?}"))
                    })
                })
            });
        }
    }
}
