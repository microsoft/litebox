// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! capture-pipe argv leaf.

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

/// Run a capture-pipe test.
/// `cmd_type`: "simple" (echo), "pipe" (echo | cat), "multi" (echo | grep | cat),
///             "noexec" (child writes directly, no exec),
///             "`nested_fork`" (fork → fork → write, no exec on either),
///             "`subshell_pipe`" (bash $()-like: fork subshell, subshell forks
///              pipeline child that execs cat, subshell waits, parent reads),
///             "`subshell_continue`" (same + parent writes more output after)
/// `shell`: "sh" or "bash" (only used for simple/pipe/multi)
pub fn run(cmd_type: &str, shell: &str) -> i32 {
    match cmd_type {
        "noexec" => run_noexec(),
        "nested_fork" => run_nested_fork(),
        "subshell_pipe" => run_subshell_pipe(),
        "subshell_continue" => run_subshell_continue(),
        _ => run_exec(cmd_type, shell),
    }
}

fn run_exec(cmd_type: &str, shell: &str) -> i32 {
    let cmd = match cmd_type {
        "simple" => "echo CAPTURE_OK",
        "pipe" => "echo CAPTURE_OK | cat",
        "multi" => "echo CAPTURE_OK | grep CAPTURE | cat",
        other => {
            eprintln!("capture-pipe: unknown cmd_type: {other}");
            eprintln!("  options: simple, pipe, multi");
            return 1;
        }
    };

    // Create capture pipe
    let mut pipe_fds = [0i32; 2];
    let rc = unsafe { libc::pipe(pipe_fds.as_mut_ptr()) };
    if rc != 0 {
        println!("CP_FAIL:pipe_err={}", std::io::Error::last_os_error());
        return 1;
    }
    let read_end = pipe_fds[0];
    let write_end = pipe_fds[1];

    // Fork
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        println!("CP_FAIL:fork_err={}", std::io::Error::last_os_error());
        return 1;
    }

    if pid == 0 {
        // Child: dup2 write end to stdout, close originals, exec shell
        unsafe {
            libc::dup2(write_end, 1);
            libc::close(read_end);
            libc::close(write_end);
        }
        let shell_c = std::ffi::CString::new(shell).unwrap();
        let flag_c = std::ffi::CString::new("-c").unwrap();
        let cmd_c = std::ffi::CString::new(cmd).unwrap();
        unsafe {
            libc::execvp(
                shell_c.as_ptr(),
                [
                    shell_c.as_ptr(),
                    flag_c.as_ptr(),
                    cmd_c.as_ptr(),
                    std::ptr::null(),
                ]
                .as_ptr(),
            );
        }
        // If exec fails
        unsafe { libc::_exit(127) };
    }

    // Parent: close write end, read from read end
    unsafe { libc::close(write_end) };

    let mut buf = [0u8; 4096];
    let mut output = Vec::new();
    loop {
        let n = unsafe { libc::read(read_end, buf.as_mut_ptr().cast(), buf.len()) };
        if n <= 0 {
            break;
        }
        output.extend_from_slice(&buf[..n as usize]);
    }
    unsafe { libc::close(read_end) };

    // Wait for child
    let mut status = 0i32;
    unsafe { libc::waitpid(pid, &raw mut status, 0) };

    let stdout = String::from_utf8_lossy(&output).trim().to_string();
    if stdout.contains("CAPTURE_OK") {
        println!("CP_OK:cmd={cmd_type},shell={shell},output={stdout}");
        0
    } else {
        println!("CP_FAIL:cmd={cmd_type},shell={shell},output={stdout},status={status}");
        1
    }
}

/// Fork without exec: child writes directly to the capture pipe.
/// This tests the delayed-fork path where the child never execs —
/// exactly what bash's $() subshell does.
fn run_noexec() -> i32 {
    let mut pipe_fds = [0i32; 2];
    if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } != 0 {
        println!("CP_FAIL:cmd=noexec,err=pipe");
        return 1;
    }
    let read_end = pipe_fds[0];
    let write_end = pipe_fds[1];

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        println!("CP_FAIL:cmd=noexec,err=fork");
        return 1;
    }

    if pid == 0 {
        // Child: close read end, write to write end, exit
        unsafe { libc::close(read_end) };
        let msg = b"CAPTURE_OK\n";
        unsafe { libc::write(write_end, msg.as_ptr().cast(), msg.len()) };
        unsafe { libc::close(write_end) };
        unsafe { libc::_exit(0) };
    }

    // Parent: close write end, read from read end
    unsafe { libc::close(write_end) };

    let mut buf = [0u8; 4096];
    let mut output = Vec::new();
    loop {
        let n = unsafe { libc::read(read_end, buf.as_mut_ptr().cast(), buf.len()) };
        if n <= 0 {
            break;
        }
        output.extend_from_slice(&buf[..n as usize]);
    }
    unsafe { libc::close(read_end) };

    let mut status = 0i32;
    unsafe { libc::waitpid(pid, &raw mut status, 0) };

    let stdout = String::from_utf8_lossy(&output).trim().to_string();
    if stdout.contains("CAPTURE_OK") {
        println!("CP_OK:cmd=noexec,shell=none,output={stdout}");
        0
    } else {
        println!("CP_FAIL:cmd=noexec,shell=none,output={stdout},status={status}");
        1
    }
}

/// Nested fork: parent forks child (subshell), child forks grandchild
/// (pipeline), grandchild writes to a pipe, child reads and forwards
/// to parent's capture pipe. This is exactly what bash does for
/// `A=$(echo hello | cat)`:
///   parent: `pipe()` → `fork()`
///   child (subshell): dup2(write,1) → `pipe()` → `fork()`
///     grandchild: `dup2(pipe_write,1)` → `write("CAPTURE_OK`") → exit
///   child: `read(pipe_read)` → write(stdout=capture) → exit
///   parent: `read(capture_read)`
fn run_nested_fork() -> i32 {
    // Capture pipe: parent reads, child writes
    let mut capture = [0i32; 2];
    if unsafe { libc::pipe(capture.as_mut_ptr()) } != 0 {
        println!("CP_FAIL:cmd=nested_fork,err=capture_pipe");
        return 1;
    }

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        println!("CP_FAIL:cmd=nested_fork,err=fork1");
        return 1;
    }

    if pid == 0 {
        // ── Child (subshell) ──
        // Redirect stdout to capture pipe
        unsafe {
            libc::dup2(capture[1], 1);
            libc::close(capture[0]);
            libc::close(capture[1]);
        }

        // Create inner pipe for "pipeline"
        let mut inner = [0i32; 2];
        if unsafe { libc::pipe(inner.as_mut_ptr()) } != 0 {
            unsafe { libc::_exit(1) };
        }

        // Fork grandchild (pipeline producer)
        let gc = unsafe { libc::fork() };
        if gc < 0 {
            // Fork failed — write error and exit
            let msg = b"FORK2_FAILED\n";
            unsafe { libc::write(1, msg.as_ptr().cast(), msg.len()) };
            unsafe { libc::_exit(1) };
        }

        if gc == 0 {
            // ── Grandchild ──
            // Write to inner pipe, exit
            unsafe { libc::close(inner[0]) };
            let msg = b"CAPTURE_OK\n";
            unsafe { libc::write(inner[1], msg.as_ptr().cast(), msg.len()) };
            unsafe { libc::close(inner[1]) };
            unsafe { libc::_exit(0) };
        }

        // ── Child continues ──
        // Read from inner pipe, write to stdout (= capture pipe)
        unsafe { libc::close(inner[1]) };
        let mut buf = [0u8; 4096];
        loop {
            let n = unsafe { libc::read(inner[0], buf.as_mut_ptr().cast(), buf.len()) };
            if n <= 0 {
                break;
            }
            unsafe { libc::write(1, buf.as_ptr().cast(), n as usize) };
        }
        unsafe { libc::close(inner[0]) };

        // Wait for grandchild
        let mut gc_status = 0i32;
        unsafe { libc::waitpid(gc, &raw mut gc_status, 0) };
        unsafe { libc::_exit(0) };
    }

    // ── Parent ──
    unsafe { libc::close(capture[1]) };

    let mut buf = [0u8; 4096];
    let mut output = Vec::new();
    loop {
        let n = unsafe { libc::read(capture[0], buf.as_mut_ptr().cast(), buf.len()) };
        if n <= 0 {
            break;
        }
        output.extend_from_slice(&buf[..n as usize]);
    }
    unsafe { libc::close(capture[0]) };

    let mut status = 0i32;
    unsafe { libc::waitpid(pid, &raw mut status, 0) };

    let stdout = String::from_utf8_lossy(&output).trim().to_string();
    if stdout.contains("CAPTURE_OK") {
        println!("CP_OK:cmd=nested_fork,shell=none,output={stdout}");
        0
    } else if stdout.contains("FORK2_FAILED") {
        println!("CP_FAIL:cmd=nested_fork,shell=none,err=second_fork_failed");
        1
    } else {
        println!("CP_FAIL:cmd=nested_fork,shell=none,output={stdout},status={status}");
        1
    }
}

/// Bash $()-like: fork subshell, subshell forks a pipeline child that
/// execs cat, subshell waits for pipeline, subshell exits, parent reads
/// capture pipe. No exec in the subshell — only the pipeline child execs.
fn run_subshell_pipe() -> i32 {
    let mut capture = [0i32; 2];
    if unsafe { libc::pipe(capture.as_mut_ptr()) } != 0 {
        println!("CP_FAIL:cmd=subshell_pipe,err=capture_pipe");
        return 1;
    }

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        println!("CP_FAIL:cmd=subshell_pipe,err=fork1");
        return 1;
    }

    if pid == 0 {
        // ── Subshell ──
        unsafe {
            libc::dup2(capture[1], 1); // stdout → capture write end
            libc::close(capture[0]);
            libc::close(capture[1]);
        }

        // Create inner pipe for "echo | cat" pipeline
        let mut inner = [0i32; 2];
        if unsafe { libc::pipe(inner.as_mut_ptr()) } != 0 {
            unsafe { libc::_exit(1) };
        }

        // Fork pipeline child (cat — reads inner pipe, writes stdout)
        let cat_pid = unsafe { libc::fork() };
        if cat_pid < 0 {
            let msg = b"FORK2_FAILED\n";
            unsafe { libc::write(1, msg.as_ptr().cast(), msg.len()) };
            unsafe { libc::_exit(1) };
        }

        if cat_pid == 0 {
            // ── Pipeline child (cat) ──
            unsafe {
                libc::dup2(inner[0], 0); // stdin ← inner read end
                libc::close(inner[0]);
                libc::close(inner[1]);
            }
            let cat = std::ffi::CString::new("/usr/bin/cat").unwrap();
            unsafe {
                libc::execvp(cat.as_ptr(), [cat.as_ptr(), std::ptr::null()].as_ptr());
                libc::_exit(127);
            }
        }

        // ── Subshell continues ──
        // Write data to inner pipe (like echo would), close write end
        unsafe { libc::close(inner[0]) };
        let msg = b"CAPTURE_OK\n";
        unsafe { libc::write(inner[1], msg.as_ptr().cast(), msg.len()) };
        unsafe { libc::close(inner[1]) };

        // Wait for cat
        let mut cat_status = 0i32;
        unsafe { libc::waitpid(cat_pid, &raw mut cat_status, 0) };
        unsafe { libc::_exit(0) };
    }

    // ── Parent ──
    unsafe { libc::close(capture[1]) };
    let output = read_all(capture[0]);
    unsafe { libc::close(capture[0]) };
    let mut status = 0i32;
    unsafe { libc::waitpid(pid, &raw mut status, 0) };

    let stdout = String::from_utf8_lossy(&output).trim().to_string();
    if stdout.contains("CAPTURE_OK") {
        println!("CP_OK:cmd=subshell_pipe,shell=none,output={stdout}");
        0
    } else {
        println!("CP_FAIL:cmd=subshell_pipe,shell=none,output={stdout},status={status}");
        1
    }
}

/// Same as `subshell_pipe`, but the parent continues writing more output
/// after reading the capture pipe. Tests that the parent's state
/// (stack, heap, `CoW` pages) is correctly restored after the vfork child
/// migrates via delayed fork.
fn run_subshell_continue() -> i32 {
    let mut capture = [0i32; 2];
    if unsafe { libc::pipe(capture.as_mut_ptr()) } != 0 {
        println!("CP_FAIL:cmd=subshell_continue,err=capture_pipe");
        return 1;
    }

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        println!("CP_FAIL:cmd=subshell_continue,err=fork1");
        return 1;
    }

    if pid == 0 {
        // ── Subshell ──
        unsafe {
            libc::dup2(capture[1], 1);
            libc::close(capture[0]);
            libc::close(capture[1]);
        }
        // Write directly (simple — no inner pipeline)
        let msg = b"SUBSHELL_DATA\n";
        unsafe { libc::write(1, msg.as_ptr().cast(), msg.len()) };
        unsafe { libc::_exit(0) };
    }

    // ── Parent continues after subshell ──
    unsafe { libc::close(capture[1]) };
    let output = read_all(capture[0]);
    unsafe { libc::close(capture[0]) };
    let mut status = 0i32;
    unsafe { libc::waitpid(pid, &raw mut status, 0) };

    let captured = String::from_utf8_lossy(&output).trim().to_string();
    // Parent does MORE WORK after reading the capture pipe.
    // This tests that the parent's state is intact after CoW restore.
    let continued = format!("CAPTURED={captured},CONTINUED=YES");
    if captured.contains("SUBSHELL_DATA") {
        println!("CP_OK:cmd=subshell_continue,shell=none,output={continued}");
        0
    } else {
        println!("CP_FAIL:cmd=subshell_continue,shell=none,output={continued},status={status}");
        1
    }
}

fn read_all(fd: i32) -> Vec<u8> {
    let mut buf = [0u8; 4096];
    let mut output = Vec::new();
    loop {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n <= 0 {
            break;
        }
        output.extend_from_slice(&buf[..n as usize]);
    }
    output
}

#[allow(dead_code)]
pub(super) const RUN: HandlerToken<LeafArgs, LeafOut> =
    HandlerToken::new("special_cases.capture_pipe.run");

#[allow(dead_code)]
pub(super) async fn handle_run(
    args: LeafArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<LeafOut, HandlerError> {
    let output = StdCommand::new(std::env::current_exe()?)
        .arg("capture-pipe")
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

/// Register the argv-only capture-pipe leaf; it intentionally tests stdio inheritance.
pub(super) fn register() {
    crate::register_handler!(RUN, handle_run);
    crate::register_leaf_subcommand!("capture-pipe", subcmd_capture_pipe);
}

fn subcmd_capture_pipe(args: &[String]) -> i32 {
    run(
        args.get(2).map_or("pipe", String::as_str),
        args.get(3).map_or("sh", String::as_str),
    )
}

/// Register capture-pipe fork tests.
pub(super) fn register_capture_pipe(reg: &mut Registry<'_>) {
    register();
    const CMD_TYPES: &[&str] = &[
        "simple",
        "pipe",
        "multi",
        "noexec",
        "nested_fork",
        "subshell_pipe",
        "subshell_continue",
    ];
    const SHELLS: &[&str] = &["sh", "bash"];
    const CP_AGENTS: &[AgentName] = &[AgentName::Dpg1, AgentName::Dpg1Dpg1];

    for &agent in CP_AGENTS {
        for &shell in SHELLS {
            for &cmd_type in CMD_TYPES {
                for &bt in crate::BinaryType::ALL {
                    let id = format!("CP.{cmd_type}.{shell}.{}.{agent}", bt.label());
                    let agent_name = agent;
                    let agent_label = agent.to_string();
                    let shell = shell.to_string();
                    let cmd_type = cmd_type.to_string();
                    typed_test!(
                        reg,
                        "fork",
                        "capture_pipe",
                        id,
                        timeout = 60,
                        agents[handle = agent_name],
                        |run| {
                            let self_exe = run.self_exe().to_string();
                            let target = crate::binary_path(bt, &self_exe);
                            let resp = run
                                .send_named_typed(
                                    &handle,
                                    &EXEC_BIN,
                                    ExecBinArgs {
                                        argv: vec![target, "capture-pipe".into(), cmd_type, shell],
                                        timeout_ms: Some(10 * 1000),
                                        stdin: None,
                                        env: vec![],
                                    },
                                )
                                .await;
                            let pass = matches!(&resp, Ok(out) if out.stdout.contains("CP_OK"));
                            crate::coordinator::TestOutcome::new(
                                &agent_label,
                                pass,
                                format!("{resp:?}"),
                            )
                        }
                    );
                }
            }
        }
    }
}
