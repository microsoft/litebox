// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Pipe bridge tests — extra pipe/socketpair fds across fork+exec.
//!
//! Tests the VS Code `child_process.fork()` pattern where extra pipes
//! beyond stdio (fds 0-2) must survive exec.  In litebox, non-PIE exec
//! goes through `exec_on_remote_host`, which currently only bridges
//! unix socket fds.  Regular pipe fds are NOT bridged, causing the
//! parent to block forever (the code-server ↔ ptyHost IPC bug).
//!
//! Test axes:
//!   - Direction: child→parent (c2p), parent→child (p2c)
//!   - Fd type: pipe (unidirectional), socketpair (bidirectional)
//!   - Binary: PIE (in-process exec), non-PIE (`exec_on_remote_host`)
//!   - Count: single pipe, multiple pipes
//!   - Agent topology: various depths (A, AA, B, NP, D4)

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::agents::{AgentName, SpawnKind};
use super::registry::Registry;
use crate::handlers::{HandlerCtx, HandlerError, HandlerToken};
use crate::{register_handler, register_leaf_subcommand};

#[derive(Serialize, Deserialize, Debug)]
struct BashArgs {
    cmd: String,
    timeout_ms: u32,
}

#[derive(Serialize, Deserialize, Debug)]
struct BashOut {
    stdout: String,
    stderr: String,
    exit_code: i32,
}

const BASH: HandlerToken<BashArgs, BashOut> = HandlerToken::new("pipe_bridge.bash");

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct PipeBridgeOut {
    pub(crate) detail: String,
}

#[derive(Serialize, Deserialize)]
struct ExtraPipeMultiArgs {
    count: usize,
}

#[derive(Serialize, Deserialize)]
struct ExtraSocketpairArgs {}

#[derive(Serialize, Deserialize)]
struct EpollPipeBridgeArgs {
    delay_ms: u64,
}

#[derive(Serialize, Deserialize)]
struct EpollSocketpairBridgeArgs {
    delay_ms: u64,
}

const EXTRA_PIPE_MULTI: HandlerToken<ExtraPipeMultiArgs, PipeBridgeOut> =
    HandlerToken::new("pipe_bridge.extra_pipe_multi");
const EXTRA_SOCKETPAIR: HandlerToken<ExtraSocketpairArgs, PipeBridgeOut> =
    HandlerToken::new("pipe_bridge.extra_socketpair");
const EPOLL_PIPE_BRIDGE: HandlerToken<EpollPipeBridgeArgs, PipeBridgeOut> =
    HandlerToken::new("pipe_bridge.epoll_pipe_bridge");
const EPOLL_SOCKETPAIR_BRIDGE: HandlerToken<EpollSocketpairBridgeArgs, PipeBridgeOut> =
    HandlerToken::new("pipe_bridge.epoll_socketpair_bridge");
pub(crate) const BIDIRECTIONAL: HandlerToken<(), PipeBridgeOut> =
    HandlerToken::new("pipe_bridge.bidirectional");

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
}

pub(crate) const fn fork_binary_label(bt: crate::BinaryType) -> &'static str {
    match bt {
        crate::BinaryType::PieGlibc => "self",
        crate::BinaryType::NonPieGlibc => "nonpie",
        crate::BinaryType::StaticPieGlibc => "static-pie-glibc",
        crate::BinaryType::StaticPieMusl => "static-pie-musl",
        crate::BinaryType::NonPieStaticMusl => "non-pie-static-musl",
    }
}

fn label_fragment(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

fn current_exe_string() -> Result<String, HandlerError> {
    Ok(std::env::current_exe()
        .map_err(|e| HandlerError(format!("current_exe: {e}")))?
        .to_str()
        .ok_or_else(|| HandlerError("current_exe is not UTF-8".into()))?
        .to_string())
}

fn read_with_poll_timeout(fd: i32, timeout_secs: u64) -> (Vec<u8>, bool) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    let mut all_data = Vec::new();
    let mut buf = [0u8; 4096];
    let mut got_eof = false;

    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            break;
        }

        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let timeout_ms = remaining.as_millis().min(1000) as i32;
        // Safety: pfd points to one valid pollfd and timeout_ms is bounded.
        let poll_ret = unsafe { libc::poll(&raw mut pfd, 1, timeout_ms) };

        if poll_ret == 0 {
            continue;
        }
        if poll_ret < 0 {
            break;
        }

        // Safety: buf is valid and fd is a test-owned pipe/socket fd.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
        if n == 0 {
            got_eof = true;
            break;
        }
        if n < 0 {
            break;
        }
        all_data.extend_from_slice(&buf[..n as usize]);
    }
    (all_data, got_eof)
}

fn wait_child(pid: i32) -> i32 {
    let mut status = 0i32;
    // Safety: pid is a child pid returned by fork in these tests.
    unsafe { libc::waitpid(pid, &raw mut status, 0) };
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        99
    }
}

fn do_execv(exe: &str, args: &[&str]) -> ! {
    let c_exe = std::ffi::CString::new(exe).unwrap();
    let c_args: Vec<std::ffi::CString> = args
        .iter()
        .map(|a| std::ffi::CString::new(*a).unwrap())
        .collect();
    let mut argv_ptrs: Vec<*const libc::c_char> = Vec::new();
    argv_ptrs.push(c_exe.as_ptr());
    for a in &c_args {
        argv_ptrs.push(a.as_ptr());
    }
    argv_ptrs.push(core::ptr::null());
    // Safety: c_exe and argv_ptrs are valid nul-terminated C strings.
    unsafe { libc::execv(c_exe.as_ptr(), argv_ptrs.as_ptr()) };
    eprintln!("[execv] failed: {}", std::io::Error::last_os_error());
    std::process::exit(127);
}

async fn handle_extra_pipe_multi(
    args: ExtraPipeMultiArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<PipeBridgeOut, HandlerError> {
    let exe = current_exe_string()?;
    Ok(PipeBridgeOut {
        detail: test_extra_pipe_multi(&exe, args.count),
    })
}

async fn handle_extra_socketpair(
    _args: ExtraSocketpairArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<PipeBridgeOut, HandlerError> {
    let exe = current_exe_string()?;
    Ok(PipeBridgeOut {
        detail: test_extra_socketpair(&exe),
    })
}

async fn handle_epoll_pipe_bridge(
    args: EpollPipeBridgeArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<PipeBridgeOut, HandlerError> {
    let exe = current_exe_string()?;
    Ok(PipeBridgeOut {
        detail: test_epoll_pipe_bridge(&exe, args.delay_ms),
    })
}

async fn handle_epoll_socketpair_bridge(
    args: EpollSocketpairBridgeArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<PipeBridgeOut, HandlerError> {
    let exe = current_exe_string()?;
    Ok(PipeBridgeOut {
        detail: test_epoll_socketpair_bridge(&exe, args.delay_ms),
    })
}

async fn handle_bidirectional(
    _args: (),
    _ctx: &mut HandlerCtx<'_>,
) -> Result<PipeBridgeOut, HandlerError> {
    Ok(PipeBridgeOut {
        detail: test_bidirectional(),
    })
}

fn test_extra_pipe_multi(exe: &str, count: usize) -> String {
    let mut pipes: Vec<[i32; 2]> = Vec::new();
    for i in 0..count {
        let mut fds = [0i32; 2];
        // Safety: fds points to two valid i32 slots for pipe to fill.
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
            return format!("PB_MULTI_PIPE_FAIL:pipe={i},errno={}", errno());
        }
        pipes.push(fds);
    }

    // Safety: this test process is single-threaded for this fork/exec probe.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return format!("PB_MULTI_FORK_FAIL:{}", errno());
    }

    if pid == 0 {
        for fds in &pipes {
            // Safety: fds[0] is a valid fd returned by pipe.
            unsafe { libc::close(fds[0]) };
        }
        let write_fds: Vec<String> = pipes.iter().map(|fds| fds[1].to_string()).collect();
        let fd_list = write_fds.join(",");
        do_execv(exe, &["pipe-test", "write-on-fd", &fd_list]);
    }

    for fds in &pipes {
        // Safety: fds[1] is a valid fd returned by pipe.
        unsafe { libc::close(fds[1]) };
    }

    let mut ok_count = 0;
    for fds in &pipes {
        let (data, _got_eof) = read_with_poll_timeout(fds[0], 15);
        // Safety: fds[0] is a valid fd returned by pipe.
        unsafe { libc::close(fds[0]) };
        let text = String::from_utf8_lossy(&data);
        if text.contains("PB_CHILD_WROTE") {
            ok_count += 1;
        }
    }

    let exit_code = wait_child(pid);
    if ok_count == count && exit_code == 0 {
        format!("PB_MULTI_OK:{count}")
    } else {
        format!("PB_MULTI_FAIL:ok={ok_count}/{count},exit={exit_code}")
    }
}

fn test_extra_socketpair(exe: &str) -> String {
    let mut fds = [0i32; 2];
    // Safety: fds points to two valid i32 slots for socketpair to fill.
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) } != 0 {
        return format!("PB_SP_SOCKETPAIR_FAIL:{}", errno());
    }

    // Safety: this test process is single-threaded for this fork/exec probe.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return format!("PB_SP_FORK_FAIL:{}", errno());
    }

    if pid == 0 {
        // Safety: fds[0] is a valid fd returned by socketpair.
        unsafe { libc::close(fds[0]) };
        let fd_str = fds[1].to_string();
        do_execv(exe, &["pipe-test", "echo-on-fd", &fd_str]);
    }

    // Safety: fds[1] is a valid fd returned by socketpair.
    unsafe { libc::close(fds[1]) };

    let msg = b"PB_SP_PING";
    // Safety: fds[0] is valid and msg points to initialized bytes.
    let written = unsafe { libc::write(fds[0], msg.as_ptr().cast::<libc::c_void>(), msg.len()) };
    if written < 0 {
        return format!("PB_SP_WRITE_FAIL:{}", errno());
    }

    let (data, _) = read_with_poll_timeout(fds[0], 15);
    // Safety: fds[0] is a valid fd returned by socketpair.
    unsafe { libc::close(fds[0]) };

    let exit_code = wait_child(pid);
    let text = String::from_utf8_lossy(&data);

    if text.contains("PB_SP_PING") && exit_code == 0 {
        "PB_SP_OK".to_string()
    } else if data.is_empty() {
        format!("PB_SP_FAIL:no_data,exit={exit_code}")
    } else {
        format!("PB_SP_FAIL:exit={exit_code},data={text}")
    }
}

fn test_epoll_pipe_bridge(exe: &str, delay_ms: u64) -> String {
    let mut pipe_fds = [0i32; 2];
    // Safety: pipe_fds points to two valid i32 slots for pipe to fill.
    if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } != 0 {
        return format!("EPOLL_BRIDGE_PIPE_FAIL:{}", errno());
    }

    // Safety: this test process is single-threaded for this fork/exec probe.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return format!("EPOLL_BRIDGE_FORK_FAIL:{}", errno());
    }

    if pid == 0 {
        // Safety: pipe_fds[0] is a valid fd returned by pipe.
        unsafe { libc::close(pipe_fds[0]) };
        let wfd_str = pipe_fds[1].to_string();
        let delay = delay_ms.to_string();
        do_execv(exe, &["pipe-test", "delayed-write-on-fd", &wfd_str, &delay]);
    }

    // Safety: pipe_fds[1] is a valid fd returned by pipe.
    unsafe { libc::close(pipe_fds[1]) };

    // Safety: pipe_fds[0] is valid; fcntl gets/sets status flags.
    unsafe {
        let flags = libc::fcntl(pipe_fds[0], libc::F_GETFL);
        libc::fcntl(pipe_fds[0], libc::F_SETFL, flags | libc::O_NONBLOCK);
    }

    // Safety: epoll_create1 is called with valid flags.
    let epfd = unsafe { libc::epoll_create1(0) };
    if epfd < 0 {
        return format!("EPOLL_BRIDGE_EPOLL_FAIL:{}", errno());
    }

    let mut ev = libc::epoll_event {
        events: libc::EPOLLIN as u32,
        u64: pipe_fds[0] as u64,
    };
    // Safety: epfd, pipe_fds[0], and ev are valid.
    if unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, pipe_fds[0], &raw mut ev) } != 0 {
        return format!("EPOLL_BRIDGE_CTL_FAIL:{}", errno());
    }

    let mut events = [libc::epoll_event { events: 0, u64: 0 }; 1];
    let t0 = std::time::Instant::now();
    // Safety: epfd is valid and events has capacity for one event.
    let nev = unsafe { libc::epoll_wait(epfd, events.as_mut_ptr(), 1, 10_000) };
    let elapsed_ms = t0.elapsed().as_millis();

    // Safety: epfd is a valid fd.
    unsafe { libc::close(epfd) };

    if nev > 0 && (events[0].events & libc::EPOLLIN as u32) != 0 {
        let mut buf = [0u8; 256];
        // Safety: pipe_fds[0] is valid and buf is initialized writable memory.
        let n = unsafe {
            libc::read(
                pipe_fds[0],
                buf.as_mut_ptr().cast::<libc::c_void>(),
                buf.len(),
            )
        };
        // Safety: pipe_fds[0] is a valid fd.
        unsafe { libc::close(pipe_fds[0]) };
        wait_child(pid);

        let data = if n > 0 {
            String::from_utf8_lossy(&buf[..n as usize]).to_string()
        } else {
            String::new()
        };

        if data.contains("PB_DELAYED_WRITE") && elapsed_ms < 5000 {
            format!("EPOLL_BRIDGE_OK:{elapsed_ms}ms")
        } else {
            format!(
                "EPOLL_BRIDGE_FAIL:data={},elapsed={elapsed_ms}ms",
                data.trim()
            )
        }
    } else if nev == 0 {
        // Safety: pipe_fds[0] is a valid fd.
        unsafe { libc::close(pipe_fds[0]) };
        wait_child(pid);
        format!("EPOLL_BRIDGE_TIMEOUT:epoll_wait returned 0 after {elapsed_ms}ms (wakeup broken)")
    } else {
        // Safety: pipe_fds[0] is a valid fd.
        unsafe { libc::close(pipe_fds[0]) };
        wait_child(pid);
        format!("EPOLL_BRIDGE_ERROR:epoll_wait={nev},errno={}", errno())
    }
}

fn test_epoll_socketpair_bridge(exe: &str, delay_ms: u64) -> String {
    let mut fds = [0i32; 2];
    // Safety: fds points to two valid i32 slots for socketpair to fill.
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) } != 0 {
        return format!("EPOLL_SP_SOCKETPAIR_FAIL:{}", errno());
    }

    // Safety: this test process is single-threaded for this fork/exec probe.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return format!("EPOLL_SP_FORK_FAIL:{}", errno());
    }

    if pid == 0 {
        // Safety: fds[0] is a valid fd returned by socketpair.
        unsafe { libc::close(fds[0]) };
        let fd_str = fds[1].to_string();
        let delay = delay_ms.to_string();
        do_execv(exe, &["pipe-test", "delayed-write-on-fd", &fd_str, &delay]);
    }

    // Safety: fds[1] is a valid fd returned by socketpair.
    unsafe { libc::close(fds[1]) };

    // Safety: fds[0] is valid; fcntl gets/sets status flags.
    unsafe {
        let flags = libc::fcntl(fds[0], libc::F_GETFL);
        libc::fcntl(fds[0], libc::F_SETFL, flags | libc::O_NONBLOCK);
    }

    // Safety: epoll_create1 is called with valid flags.
    let epfd = unsafe { libc::epoll_create1(0) };
    if epfd < 0 {
        return format!("EPOLL_SP_EPOLL_FAIL:{}", errno());
    }

    let mut ev = libc::epoll_event {
        events: libc::EPOLLIN as u32,
        u64: fds[0] as u64,
    };
    // Safety: epfd, fds[0], and ev are valid.
    if unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, fds[0], &raw mut ev) } != 0 {
        return format!("EPOLL_SP_CTL_FAIL:{}", errno());
    }

    let mut spin_count: u32 = 0;
    let mut events = [libc::epoll_event { events: 0, u64: 0 }; 1];
    let t0 = std::time::Instant::now();
    let deadline = t0 + std::time::Duration::from_secs(10);

    loop {
        let remaining_ms = deadline
            .saturating_duration_since(std::time::Instant::now())
            .as_millis()
            .min(1000) as i32;
        if remaining_ms == 0 {
            break;
        }

        // Safety: epfd is valid and events has capacity for one event.
        let nev = unsafe { libc::epoll_wait(epfd, events.as_mut_ptr(), 1, remaining_ms) };

        if nev > 0 && (events[0].events & libc::EPOLLIN as u32) != 0 {
            let elapsed_ms = t0.elapsed().as_millis();
            let mut buf = [0u8; 256];
            // Safety: fds[0] is valid and buf is initialized writable memory.
            let n =
                unsafe { libc::read(fds[0], buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
            // Safety: fds[0] and epfd are valid fds.
            unsafe {
                libc::close(fds[0]);
                libc::close(epfd);
            }
            wait_child(pid);
            let data = if n > 0 {
                String::from_utf8_lossy(&buf[..n as usize]).to_string()
            } else {
                String::new()
            };
            if data.contains("PB_DELAYED_WRITE") && elapsed_ms < 5000 && spin_count < 50 {
                return format!("EPOLL_SP_OK:{elapsed_ms}ms,spins={spin_count}");
            }
            return format!(
                "EPOLL_SP_FAIL:elapsed={elapsed_ms}ms,spins={spin_count},data={}",
                data.trim()
            );
        } else if nev == 0 {
            spin_count += 1;
        } else {
            break;
        }
    }

    // Safety: fds[0] and epfd are valid fds.
    unsafe {
        libc::close(fds[0]);
        libc::close(epfd);
    }
    wait_child(pid);
    let elapsed_ms = t0.elapsed().as_millis();
    format!("EPOLL_SP_TIMEOUT:elapsed={elapsed_ms}ms,spins={spin_count} (wakeup broken)")
}

fn test_bidirectional() -> String {
    let sock_path = "/tmp/litebox-us3-test.sock";
    let _ = std::fs::remove_file(sock_path);

    // Safety: this test process is single-threaded for this fork probe.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return format!("US3_FORK_FAIL:{}", errno());
    }

    if pid == 0 {
        let listener = match UnixListener::bind(sock_path) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("[US3-server] bind: {e}");
                std::process::exit(1);
            }
        };
        match listener.accept() {
            Ok((mut stream, _)) => {
                let mut buf = [0u8; 64];
                let n = stream.read(&mut buf).unwrap_or(0);
                let _ = stream.write_all(b"SERVER_DATA");
                let msg = std::str::from_utf8(&buf[..n]).unwrap_or("?");
                std::process::exit(if msg == "CLIENT_DATA" { 0 } else { 2 });
            }
            Err(_) => std::process::exit(3),
        }
    }

    std::thread::sleep(std::time::Duration::from_millis(200));
    let mut stream = None;
    for _ in 0..10 {
        if let Ok(s) = UnixStream::connect(sock_path) {
            stream = Some(s);
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    let Some(mut stream) = stream else {
        let _ = wait_child(pid);
        return "US3_CONNECT_FAIL".to_string();
    };

    let _ = stream.write_all(b"CLIENT_DATA");
    let mut buf = [0u8; 64];
    let n = stream.read(&mut buf).unwrap_or(0);
    let reply = std::str::from_utf8(&buf[..n]).unwrap_or("?").to_string();
    drop(stream);

    let exit_code = wait_child(pid);
    let _ = std::fs::remove_file(sock_path);

    if reply == "SERVER_DATA" && exit_code == 0 {
        "US3_BIDI_OK".to_string()
    } else {
        format!("US3_BIDI_FAIL:reply={reply},exit={exit_code}")
    }
}

async fn handle_bash(args: BashArgs, _ctx: &mut HandlerCtx<'_>) -> Result<BashOut, HandlerError> {
    let output = tokio::time::timeout(
        Duration::from_millis(u64::from(args.timeout_ms)),
        tokio::process::Command::new("bash")
            .arg("-c")
            .arg(&args.cmd)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| HandlerError(format!("bash timed out after {} ms", args.timeout_ms)))??;

    Ok(BashOut {
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        exit_code: output.status.code().unwrap_or(-1),
    })
}

fn bash_cmd(args: &[String]) -> String {
    args.iter()
        .map(|arg| shell_quote(arg))
        .collect::<Vec<_>>()
        .join(" ")
}

fn shell_quote(arg: &str) -> String {
    if !arg.is_empty()
        && arg
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'_' | b'-' | b'='))
    {
        return arg.to_string();
    }

    format!("'{}'", arg.replace('\'', "'\\''"))
}

fn timeout_ms(seconds: u64) -> u32 {
    seconds.saturating_mul(1000).min(u64::from(u32::MAX)) as u32
}

/// Agents for pipe bridge tests.  Includes depths 1-2 and the
/// non-PIE worker agent (NP) to test nested worker-exec.
const PB_AGENTS: &[AgentName] = &[AgentName::Dpg1, AgentName::Dpg1Dpg1, AgentName::Dpg2];

#[allow(clippy::too_many_lines)] // exhaustive registration / runner
pub(crate) fn register_pipe_bridge(reg: &mut Registry<'_>) {
    register_handler!(BASH, handle_bash);
    register_handler!(EXTRA_PIPE_MULTI, handle_extra_pipe_multi);
    register_handler!(EXTRA_SOCKETPAIR, handle_extra_socketpair);
    register_handler!(EPOLL_PIPE_BRIDGE, handle_epoll_pipe_bridge);
    register_handler!(EPOLL_SOCKETPAIR_BRIDGE, handle_epoll_socketpair_bridge);
    register_handler!(BIDIRECTIONAL, handle_bidirectional);
    register_leaf_subcommand!("pipe-test", subcmd_pipe_test);
    // Also expose `bidirectional` as an argv subcommand for the
    // US3 test family. The leaf-agent form (via run_leaf on
    // BIDIRECTIONAL) times out under litebox for PIE-glibc — the
    // test internally does libc::fork inside the leaf agent's
    // handler, which interacts poorly with the litebox shim for
    // some binary types. The argv form preserves the pre-wave-8
    // semantics (test runs in a fresh exec'd subcommand child).
    register_leaf_subcommand!("bidirectional", |_args: &[String]| -> i32 {
        let out = test_bidirectional();
        println!("{out}");
        if out == "US3_BIDI_OK" { 0 } else { 1 }
    });

    struct PbCase {
        mode: &'static str,
        subcmd: &'static str,
        extra_args: &'static [&'static str],
        expected: &'static str,
        agents: &'static [AgentName],
        timeout: u64,
    }

    const XWORKER_AGENTS: &[AgentName] = &[AgentName::Dpg1Dng];

    let cases: &[PbCase] = &[
        PbCase {
            mode: "c2p",
            subcmd: "extra-pipe-c2p",
            extra_args: &[],
            expected: "PB_C2P_OK",
            agents: PB_AGENTS,
            timeout: 20,
        },
        PbCase {
            mode: "p2c",
            subcmd: "extra-pipe-p2c",
            extra_args: &[],
            expected: "PB_P2C_OK",
            agents: PB_AGENTS,
            timeout: 20,
        },
        PbCase {
            mode: "multi",
            subcmd: "extra-pipe-multi",
            extra_args: &["3"],
            expected: "PB_MULTI_OK",
            agents: PB_AGENTS,
            timeout: 20,
        },
        PbCase {
            mode: "sp",
            subcmd: "extra-socketpair",
            extra_args: &[],
            expected: "PB_SP_OK",
            agents: PB_AGENTS,
            timeout: 20,
        },
        PbCase {
            mode: "c2p.xworker",
            subcmd: "extra-pipe-c2p",
            extra_args: &[],
            expected: "PB_C2P_OK",
            agents: XWORKER_AGENTS,
            timeout: 20,
        },
        PbCase {
            mode: "many",
            subcmd: "extra-pipe-multi",
            extra_args: &["10"],
            expected: "PB_MULTI_OK",
            agents: PB_AGENTS,
            timeout: 20,
        },
        PbCase {
            mode: "epoll",
            subcmd: "epoll-pipe-bridge",
            extra_args: &["200"],
            expected: "EPOLL_BRIDGE_OK",
            agents: PB_AGENTS,
            timeout: 15,
        },
        PbCase {
            mode: "epoll_sp",
            subcmd: "epoll-socketpair-bridge",
            extra_args: &["500"],
            expected: "EPOLL_SP_OK",
            agents: PB_AGENTS,
            timeout: 15,
        },
    ];

    for case in cases {
        for &bt in crate::BinaryType::ALL {
            let bt_label = bt.label();
            for &agent in case.agents {
                let id = format!("PB.{}.{bt_label}.{agent}", case.mode);
                let subcmd = case.subcmd.to_string();
                let extra: Vec<String> = case
                    .extra_args
                    .iter()
                    .map(std::string::ToString::to_string)
                    .collect();
                let expected = case.expected.to_string();
                let timeout = case.timeout;
                let agent_label = agent.to_string();

                reg.test("xworker", "pipe_bridge", id)
                    .timeout(90)
                    .build(move |cx| {
                        let migrated = matches!(
                            subcmd.as_str(),
                            "extra-pipe-multi"
                                | "extra-socketpair"
                                | "epoll-pipe-bridge"
                                | "epoll-socketpair-bridge"
                        );
                        let handle = (!migrated).then(|| cx.require(agent));
                        let leaf = migrated.then(|| {
                            cx.declare_ephemeral(
                                agent,
                                format!("Pb_{}_{}", label_fragment(&case.mode), bt.short_label()),
                                SpawnKind::Fork {
                                    binary: fork_binary_label(bt),
                                    inherit_listen_ports: vec![],
                                },
                            )
                        });
                        Box::new(move |run| {
                            let extra = extra.clone();
                            let agent_label = agent_label.clone();
                            let handle = handle.clone();
                            let leaf = leaf.clone();
                            Box::pin(async move {
                                let detail = match subcmd.as_str() {
                                    "extra-pipe-multi" => {
                                        let count =
                                            extra.first().and_then(|s| s.parse().ok()).unwrap_or(3);
                                        run.run_leaf(
                                            leaf.as_ref().expect("migrated leaf"),
                                            &EXTRA_PIPE_MULTI,
                                            ExtraPipeMultiArgs { count },
                                        )
                                        .await
                                        .map(|out| out.detail)
                                    }
                                    "extra-socketpair" => run
                                        .run_leaf(
                                            leaf.as_ref().expect("migrated leaf"),
                                            &EXTRA_SOCKETPAIR,
                                            ExtraSocketpairArgs {},
                                        )
                                        .await
                                        .map(|out| out.detail),
                                    "epoll-pipe-bridge" => {
                                        let delay_ms = extra
                                            .first()
                                            .and_then(|s| s.parse().ok())
                                            .unwrap_or(200);
                                        run.run_leaf(
                                            leaf.as_ref().expect("migrated leaf"),
                                            &EPOLL_PIPE_BRIDGE,
                                            EpollPipeBridgeArgs { delay_ms },
                                        )
                                        .await
                                        .map(|out| out.detail)
                                    }
                                    "epoll-socketpair-bridge" => {
                                        let delay_ms = extra
                                            .first()
                                            .and_then(|s| s.parse().ok())
                                            .unwrap_or(500);
                                        run.run_leaf(
                                            leaf.as_ref().expect("migrated leaf"),
                                            &EPOLL_SOCKETPAIR_BRIDGE,
                                            EpollSocketpairBridgeArgs { delay_ms },
                                        )
                                        .await
                                        .map(|out| out.detail)
                                    }
                                    _ => {
                                        let self_exe = run.self_exe().to_string();
                                        let child_bin = crate::binary_path(bt, &self_exe);
                                        let mut args =
                                            vec![self_exe, "pipe-test".into(), subcmd, child_bin];
                                        args.extend(extra);
                                        run.send_named_typed(
                                            handle.as_ref().expect("argv handle"),
                                            &BASH,
                                            BashArgs {
                                                cmd: bash_cmd(&args),
                                                timeout_ms: timeout_ms(timeout),
                                            },
                                        )
                                        .await
                                        .map(|out| {
                                            if out.exit_code == 0 {
                                                out.stdout
                                            } else {
                                                format!(
                                                    "exit={} stdout={} stderr={}",
                                                    out.exit_code, out.stdout, out.stderr
                                                )
                                            }
                                        })
                                        .map_err(|e| format!("{e:?}"))
                                    }
                                };
                                let pass = matches!(&detail, Ok(s) if s.contains(&*expected));
                                super::TestOutcome::new(&agent_label, pass, format!("{detail:?}"))
                            })
                        })
                    });
            }
        }
    }

    for &(mode, subcmd, expected) in &[
        ("sibling_dual.c2p", "extra-pipe-c2p", "PB_C2P_OK"),
        ("sibling_dual.p2c", "extra-pipe-p2c", "PB_P2C_OK"),
        ("sibling_dual.sp", "extra-socketpair", "PB_SP_OK"),
    ] {
        let id = format!("PB.{mode}");
        reg.test("xworker", "pipe_bridge", id)
            .timeout(90)
            .build(move |cx| {
                let migrated = subcmd == "extra-socketpair";
                let left = (!migrated).then(|| cx.require(AgentName::Dpg1Dpg1));
                let right = (!migrated).then(|| cx.require(AgentName::Dpg1Dpg2));
                let left_leaf = migrated.then(|| {
                    cx.declare_ephemeral(
                        AgentName::Dpg1Dpg1,
                        format!("Pb_{}_left", label_fragment(mode)),
                        SpawnKind::Fork {
                            binary: "self",
                            inherit_listen_ports: vec![],
                        },
                    )
                });
                let right_leaf = migrated.then(|| {
                    cx.declare_ephemeral(
                        AgentName::Dpg1Dpg2,
                        format!("Pb_{}_right", label_fragment(mode)),
                        SpawnKind::Fork {
                            binary: "self",
                            inherit_listen_ports: vec![],
                        },
                    )
                });
                Box::new(move |run| {
                    let left = left.clone();
                    let right = right.clone();
                    let left_leaf = left_leaf.clone();
                    let right_leaf = right_leaf.clone();
                    Box::pin(async move {
                        if migrated {
                            let left_resp = run
                                .run_leaf(
                                    left_leaf.as_ref().expect("left leaf"),
                                    &EXTRA_SOCKETPAIR,
                                    ExtraSocketpairArgs {},
                                )
                                .await
                                .map(|out| out.detail);
                            let right_resp = run
                                .run_leaf(
                                    right_leaf.as_ref().expect("right leaf"),
                                    &EXTRA_SOCKETPAIR,
                                    ExtraSocketpairArgs {},
                                )
                                .await
                                .map(|out| out.detail);
                            let left_ok = matches!(&left_resp, Ok(out) if out.trim() == expected);
                            let right_ok = matches!(&right_resp, Ok(out) if out.trim() == expected);
                            return super::TestOutcome::new(
                                "AA+AB",
                                left_ok && right_ok,
                                format!("left={left_resp:?} right={right_resp:?}"),
                            );
                        }

                        let self_exe = run.self_exe().to_string();
                        let args = |subcmd: &str| {
                            vec![
                                self_exe.clone(),
                                "pipe-test".into(),
                                subcmd.to_string(),
                                self_exe.clone(),
                            ]
                        };
                        let left_args = args(subcmd);
                        let left_resp = run
                            .send_named_typed(
                                left.as_ref().expect("left argv handle"),
                                &BASH,
                                BashArgs {
                                    cmd: bash_cmd(&left_args),
                                    timeout_ms: timeout_ms(20),
                                },
                            )
                            .await;
                        let right_args = args(subcmd);
                        let right_resp = run
                            .send_named_typed(
                                right.as_ref().expect("right argv handle"),
                                &BASH,
                                BashArgs {
                                    cmd: bash_cmd(&right_args),
                                    timeout_ms: timeout_ms(20),
                                },
                            )
                            .await;
                        let left_ok = matches!(
                            &left_resp,
                            Ok(out) if out.exit_code == 0 && out.stdout.trim() == expected
                        );
                        let right_ok = matches!(
                            &right_resp,
                            Ok(out) if out.exit_code == 0 && out.stdout.trim() == expected
                        );
                        super::TestOutcome::new(
                            "AA+AB",
                            left_ok && right_ok,
                            format!("left={left_resp:?} right={right_resp:?}"),
                        )
                    })
                })
            });
    }
}

/// `pipe-test` remains an argv leaf dispatcher for fd-inheritance helpers and
/// pipe EOF probes: these subcommands intentionally inherit non-protocol fds or
/// stdio across a raw exec, which a handler-dispatched agent must not own.
fn subcmd_pipe_test(args: &[String]) -> i32 {
    match args.get(2).map_or("help", String::as_str) {
        "eof-fork" => subcmd_eof_fork(),
        "eof-exec" => subcmd_eof_exec(args),
        "echo-exit" => {
            println!("PIPE_CHILD_DATA");
            0
        }
        "extra-pipe-c2p" => subcmd_extra_pipe_c2p(args),
        "extra-pipe-p2c" => subcmd_extra_pipe_p2c(args),
        "write-on-fd" => subcmd_write_on_fd(args),
        "read-on-fd" => subcmd_read_on_fd(args),
        "echo-on-fd" => subcmd_echo_on_fd(args),
        "delayed-write-on-fd" => subcmd_delayed_write_on_fd(args),
        other => {
            eprintln!("unknown pipe-test: {other}");
            1
        }
    }
}

fn subcmd_default_exe(args: &[String]) -> String {
    args.get(3).cloned().unwrap_or_else(|| {
        std::env::current_exe()
            .unwrap()
            .to_str()
            .unwrap()
            .to_string()
    })
}

fn subcmd_eof_fork() -> i32 {
    let mut pipe_fds = [0i32; 2];
    // Safety: pipe_fds points to two valid i32 slots for pipe to fill.
    if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } != 0 {
        println!("P1_PIPE_FAIL:{}", errno());
        return 1;
    }

    // Safety: this argv leaf is single-threaded for the fork probe.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        println!("P1_FORK_FAIL:{}", errno());
        return 1;
    }

    if pid == 0 {
        // Safety: pipe_fds are valid fds returned by pipe.
        unsafe {
            libc::close(pipe_fds[0]);
            let msg = b"P1_CHILD_DATA\n";
            let _ = libc::write(pipe_fds[1], msg.as_ptr().cast::<libc::c_void>(), msg.len());
            libc::close(pipe_fds[1]);
        }
        std::process::exit(0);
    }

    // Safety: pipe_fds[1] is a valid fd returned by pipe.
    unsafe { libc::close(pipe_fds[1]) };
    let (data, _) = read_with_poll_timeout(pipe_fds[0], 15);
    // Safety: pipe_fds[0] is a valid fd returned by pipe.
    unsafe { libc::close(pipe_fds[0]) };
    let _ = wait_child(pid);
    let data = String::from_utf8_lossy(&data);
    if data.contains("P1_CHILD_DATA") {
        println!("P1_EOF_OK");
        0
    } else {
        println!("P1_EOF_FAIL:data={data}");
        1
    }
}

fn subcmd_eof_exec(args: &[String]) -> i32 {
    let exe = subcmd_default_exe(args);
    let mut pipe_fds = [0i32; 2];
    // Safety: pipe_fds points to two valid i32 slots for pipe to fill.
    if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } != 0 {
        println!("P2_PIPE_FAIL:{}", errno());
        return 1;
    }

    // Safety: this argv leaf is single-threaded for the fork/exec probe.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        println!("P2_FORK_FAIL:{}", errno());
        return 1;
    }

    if pid == 0 {
        // Safety: pipe_fds are valid; dup2 redirects stdout to the pipe write end.
        unsafe {
            libc::close(pipe_fds[0]);
            libc::dup2(pipe_fds[1], 1);
            libc::close(pipe_fds[1]);
        }
        do_execv(&exe, &["pipe-test", "echo-exit"]);
    }

    // Safety: pipe_fds[1] is a valid fd returned by pipe.
    unsafe { libc::close(pipe_fds[1]) };
    let (data, _) = read_with_poll_timeout(pipe_fds[0], 15);
    // Safety: pipe_fds[0] is a valid fd returned by pipe.
    unsafe { libc::close(pipe_fds[0]) };
    let exit_code = wait_child(pid);
    let data = String::from_utf8_lossy(&data);
    if data.contains("PIPE_CHILD_DATA") && exit_code == 0 {
        println!("P2_EOF_OK");
        0
    } else {
        println!("P2_EOF_FAIL:exit={exit_code},data={data}");
        1
    }
}

fn subcmd_extra_pipe_c2p(args: &[String]) -> i32 {
    let exe = subcmd_default_exe(args);
    let mut pipe_fds = [0i32; 2];
    // Safety: pipe_fds points to two valid i32 slots for pipe to fill.
    if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } != 0 {
        println!("PB_C2P_PIPE_FAIL:{}", errno());
        return 1;
    }

    // Safety: this argv leaf is single-threaded for the fork/exec probe.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        println!("PB_C2P_FORK_FAIL:{}", errno());
        return 1;
    }

    if pid == 0 {
        // Safety: pipe_fds[0] is a valid fd returned by pipe.
        unsafe { libc::close(pipe_fds[0]) };
        let wfd_str = pipe_fds[1].to_string();
        do_execv(&exe, &["pipe-test", "write-on-fd", &wfd_str]);
    }

    // Safety: pipe_fds[1] is a valid fd returned by pipe.
    unsafe { libc::close(pipe_fds[1]) };
    let (data, _) = read_with_poll_timeout(pipe_fds[0], 15);
    // Safety: pipe_fds[0] is a valid fd returned by pipe.
    unsafe { libc::close(pipe_fds[0]) };
    let exit_code = wait_child(pid);
    let text = String::from_utf8_lossy(&data);
    if text.contains("PB_CHILD_WROTE") && exit_code == 0 {
        println!("PB_C2P_OK");
        0
    } else if data.is_empty() {
        println!(
            "PB_C2P_FAIL:no_data (pipe fd likely not bridged to child worker), exit={exit_code}"
        );
        1
    } else {
        println!("PB_C2P_FAIL:exit={exit_code},data={text}");
        1
    }
}

fn subcmd_extra_pipe_p2c(args: &[String]) -> i32 {
    let exe = subcmd_default_exe(args);
    let mut pipe_fds = [0i32; 2];
    // Safety: pipe_fds points to two valid i32 slots for pipe to fill.
    if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } != 0 {
        println!("PB_P2C_PIPE_FAIL:{}", errno());
        return 1;
    }

    // Safety: this argv leaf is single-threaded for the fork/exec probe.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        println!("PB_P2C_FORK_FAIL:{}", errno());
        return 1;
    }

    if pid == 0 {
        // Safety: pipe_fds[1] is a valid fd returned by pipe.
        unsafe { libc::close(pipe_fds[1]) };
        let rfd_str = pipe_fds[0].to_string();
        do_execv(&exe, &["pipe-test", "read-on-fd", &rfd_str]);
    }

    // Safety: pipe_fds[0] is a valid fd returned by pipe.
    unsafe { libc::close(pipe_fds[0]) };
    let msg = b"PB_PARENT_WROTE\n";
    // Safety: pipe_fds[1] is valid and msg points to initialized bytes.
    let written =
        unsafe { libc::write(pipe_fds[1], msg.as_ptr().cast::<libc::c_void>(), msg.len()) };
    // Safety: pipe_fds[1] is a valid fd returned by pipe.
    unsafe { libc::close(pipe_fds[1]) };
    if written < 0 {
        println!("PB_P2C_WRITE_FAIL:{}", errno());
        return 1;
    }
    let exit_code = wait_child(pid);
    if exit_code == 0 {
        println!("PB_P2C_OK");
        0
    } else {
        println!("PB_P2C_FAIL:exit={exit_code}");
        1
    }
}

fn subcmd_write_on_fd(args: &[String]) -> i32 {
    let fd_arg = args.get(3).map_or("3", String::as_str);
    let fds: Vec<i32> = fd_arg.split(',').filter_map(|s| s.parse().ok()).collect();
    if fds.is_empty() {
        eprintln!("[write-on-fd] no valid fds in: {fd_arg}");
        return 1;
    }
    let mut ok = true;
    for &fd in &fds {
        let msg = format!("PB_CHILD_WROTE:fd={fd}\n");
        // Safety: fd is inherited from the parent test process and msg is valid.
        let n = unsafe { libc::write(fd, msg.as_ptr().cast::<libc::c_void>(), msg.len()) };
        if n < 0 {
            eprintln!(
                "[write-on-fd] write(fd={fd}) failed: {}",
                std::io::Error::last_os_error()
            );
            ok = false;
        }
        // Safety: fd is an inherited test fd that this helper owns.
        unsafe { libc::close(fd) };
    }
    i32::from(!ok)
}

fn subcmd_read_on_fd(args: &[String]) -> i32 {
    let fd: i32 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(3);
    let (data, _) = read_with_poll_timeout(fd, 10);
    // Safety: fd is an inherited test fd that this helper owns.
    unsafe { libc::close(fd) };
    let text = String::from_utf8_lossy(&data);
    if text.contains("PB_PARENT_WROTE") {
        eprintln!("[read-on-fd] got: {text}");
        0
    } else {
        eprintln!("[read-on-fd] expected PB_PARENT_WROTE, got: {text}");
        1
    }
}

fn subcmd_echo_on_fd(args: &[String]) -> i32 {
    let fd: i32 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(3);
    let mut buf = [0u8; 4096];
    // Safety: fd is inherited from the parent test process and buf is valid.
    let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
    if n <= 0 {
        eprintln!(
            "[echo-on-fd] read failed: {}",
            std::io::Error::last_os_error()
        );
        // Safety: fd is an inherited test fd that this helper owns.
        unsafe { libc::close(fd) };
        return 1;
    }
    let n = n as usize;
    // Safety: fd is valid and buf[..n] contains bytes just read.
    let w = unsafe { libc::write(fd, buf.as_ptr().cast::<libc::c_void>(), n) };
    // Safety: fd is an inherited test fd that this helper owns.
    unsafe { libc::close(fd) };
    i32::from(w < 0)
}

fn subcmd_delayed_write_on_fd(args: &[String]) -> i32 {
    let fd_arg = args.get(3).map_or("3", String::as_str);
    let delay_ms: u64 = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(500);
    let fds: Vec<i32> = fd_arg.split(',').filter_map(|s| s.parse().ok()).collect();
    std::thread::sleep(std::time::Duration::from_millis(delay_ms));
    let mut ok = true;
    for &fd in &fds {
        let msg = format!("PB_DELAYED_WRITE:fd={fd}\n");
        // Safety: fd is inherited from the parent test process and msg is valid.
        let n = unsafe { libc::write(fd, msg.as_ptr().cast::<libc::c_void>(), msg.len()) };
        if n < 0 {
            eprintln!(
                "[delayed-write] write(fd={fd}) failed: {}",
                std::io::Error::last_os_error()
            );
            ok = false;
        }
        // Safety: fd is an inherited test fd that this helper owns.
        unsafe { libc::close(fd) };
    }
    i32::from(!ok)
}
