// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Platform fix validation tests — matrix-loop tests that prove specific bug
//! fixes are needed by exercising the exact behavior each fix corrected.
//!
//! Each test category targets a commit in the wportnoy/vscode-server-in-litebox
//! branch and must pass on both native WSL2 (gold standard) and litebox.

#![allow(clippy::items_after_statements)]

use std::collections::HashMap;
use std::os::fd::FromRawFd;
use std::process::Stdio;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration as StdDuration, Instant};

use serde::{Deserialize, Serialize};

use crate::handlers::{HandlerCtx, HandlerError, HandlerToken};
use crate::protocol::{Command as InfraCommand, Response};
use crate::register_handler;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::Duration;

use super::agents::{AgentHandle, AgentName, EphemeralHandle, SpawnKind};
use super::registry::Registry;
use super::run_context::RunContext;

const AGENTS: &[AgentName] = &[AgentName::Dpg1, AgentName::Dpg1Dpg1, AgentName::Dpg2];
const DEPTH_AGENTS: &[AgentName] = &[AgentName::Dpg1, AgentName::Dpg1Dpg1];

#[derive(Serialize, Deserialize, Debug)]
struct DetailOut {
    detail: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct PollReadyArgs {
    timeout_ms: u32,
}

#[derive(Serialize, Deserialize, Debug)]
struct BindGetsocknameArgs {
    family: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct PipePairIdArgs {
    count: u32,
}

#[derive(Serialize, Deserialize, Debug)]
struct AcceptInheritedArgs {
    port: u16,
    timeout_secs: u64,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
struct PfExecArgs {
    args: Vec<String>,
    timeout_secs: Option<u64>,
    stdin: Option<String>,
    background: bool,
    env: Vec<(String, String)>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
struct PfExecReadyArgs {
    args: Vec<String>,
    ready_marker: String,
    timeout_secs: Option<u64>,
    stdin: Option<String>,
    stream: String,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
struct PfPathArgs {
    path: String,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
struct PfKillArgs {
    pid: u32,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
struct PfNetListenArgs {
    port: u16,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
struct PfNetConnectArgs {
    addr: String,
    data: String,
}

const POLL_READY: HandlerToken<PollReadyArgs, DetailOut> =
    HandlerToken::new("platform_fixes.poll_ready");
const BIND_GETSOCKNAME: HandlerToken<BindGetsocknameArgs, DetailOut> =
    HandlerToken::new("platform_fixes.bind_getsockname");
const PIPE_PAIR_ID: HandlerToken<PipePairIdArgs, DetailOut> =
    HandlerToken::new("platform_fixes.pipe_pair_id");
const ACCEPT_INHERITED: HandlerToken<AcceptInheritedArgs, DetailOut> =
    HandlerToken::new("platform_fixes.accept_inherited");

const PF_EXEC: HandlerToken<PfExecArgs, Response> = HandlerToken::new("platform_fixes.exec");
const PF_EXEC_READY: HandlerToken<PfExecReadyArgs, Response> =
    HandlerToken::new("platform_fixes.exec_ready");
const PF_FS_READ: HandlerToken<PfPathArgs, Response> = HandlerToken::new("platform_fixes.fs_read");
const PF_FS_DELETE: HandlerToken<PfPathArgs, Response> =
    HandlerToken::new("platform_fixes.fs_delete");
const PF_KILL: HandlerToken<PfKillArgs, Response> = HandlerToken::new("platform_fixes.kill");
const PF_GET_PID: HandlerToken<(), Response> = HandlerToken::new("platform_fixes.get_pid");
const PF_NET_LISTEN: HandlerToken<PfNetListenArgs, Response> =
    HandlerToken::new("platform_fixes.net_listen");
const PF_NET_UNLISTEN: HandlerToken<PfNetListenArgs, Response> =
    HandlerToken::new("platform_fixes.net_unlisten");
const PF_NET_CONNECT: HandlerToken<PfNetConnectArgs, Response> =
    HandlerToken::new("platform_fixes.net_connect");

#[derive(Serialize, Deserialize, Debug)]
struct CliStartupMimicArgs {}

#[derive(Serialize, Deserialize, Debug)]
struct ForkExecPieArgs {
    binary: String,
    subcommand: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct PipeNonblockArgs {}

#[derive(Serialize, Deserialize, Debug)]
struct PipeChildNonblockArgs {}

#[derive(Serialize, Deserialize, Debug)]
struct EpollSocketArgs {
    port: u16,
    variant: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct CrossWorkerFileArgs {
    mode: String,
    path: String,
}

const CLI_STARTUP_MIMIC: HandlerToken<CliStartupMimicArgs, DetailOut> =
    HandlerToken::new("platform_fixes.cli_startup_mimic");
const FORK_EXEC_PIE: HandlerToken<ForkExecPieArgs, DetailOut> =
    HandlerToken::new("platform_fixes.fork_exec_pie");
const PIPE_NONBLOCK: HandlerToken<PipeNonblockArgs, DetailOut> =
    HandlerToken::new("platform_fixes.pipe_nonblock");
const PIPE_CHILD_NONBLOCK: HandlerToken<PipeChildNonblockArgs, DetailOut> =
    HandlerToken::new("platform_fixes.pipe_child_nonblock");
const EPOLL_SOCKET: HandlerToken<EpollSocketArgs, DetailOut> =
    HandlerToken::new("platform_fixes.epoll_socket");
const CROSS_WORKER_FILE: HandlerToken<CrossWorkerFileArgs, DetailOut> =
    HandlerToken::new("platform_fixes.cross_worker_file");

static PF_TCP_LISTENERS: OnceLock<Mutex<HashMap<u16, tokio::task::JoinHandle<()>>>> =
    OnceLock::new();

fn pf_tcp_listeners() -> &'static Mutex<HashMap<u16, tokio::task::JoinHandle<()>>> {
    PF_TCP_LISTENERS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn pf_exec_args(args: Vec<String>) -> PfExecArgs {
    PfExecArgs {
        args,
        timeout_secs: None,
        stdin: None,
        background: false,
        env: vec![],
    }
}

fn pf_exec_timeout_args(args: Vec<String>, timeout_secs: u64) -> PfExecArgs {
    PfExecArgs {
        timeout_secs: Some(timeout_secs),
        ..pf_exec_args(args)
    }
}

async fn pf_send_response<A>(
    run: &mut RunContext<'_>,
    handle: &AgentHandle,
    token: &'static HandlerToken<A, Response>,
    args: A,
) -> Response
where
    A: serde::Serialize,
{
    run.send_named_typed(handle, token, args)
        .await
        .unwrap_or_else(|e| Response::Error { error: e })
}

async fn pf_exec(run: &mut RunContext<'_>, handle: &AgentHandle, args: Vec<String>) -> Response {
    pf_send_response(run, handle, &PF_EXEC, pf_exec_args(args)).await
}

async fn pf_exec_full(
    run: &mut RunContext<'_>,
    handle: &AgentHandle,
    args: Vec<String>,
    timeout_secs: Option<u64>,
    stdin: Option<String>,
    env: Vec<(String, String)>,
) -> Response {
    pf_send_response(
        run,
        handle,
        &PF_EXEC,
        PfExecArgs {
            args,
            timeout_secs,
            stdin,
            background: false,
            env,
        },
    )
    .await
}

async fn pf_exec_ready(
    run: &mut RunContext<'_>,
    handle: &AgentHandle,
    args: Vec<String>,
    ready_marker: String,
    timeout_secs: Option<u64>,
    stdin: Option<String>,
    stream: String,
) -> Response {
    pf_send_response(
        run,
        handle,
        &PF_EXEC_READY,
        PfExecReadyArgs {
            args,
            ready_marker,
            timeout_secs,
            stdin,
            stream,
        },
    )
    .await
}

async fn pf_fs_read(run: &mut RunContext<'_>, handle: &AgentHandle, path: String) -> Response {
    pf_send_response(run, handle, &PF_FS_READ, PfPathArgs { path }).await
}

async fn pf_fs_delete(run: &mut RunContext<'_>, handle: &AgentHandle, path: String) -> Response {
    pf_send_response(run, handle, &PF_FS_DELETE, PfPathArgs { path }).await
}

async fn pf_kill(run: &mut RunContext<'_>, handle: &AgentHandle, pid: u32) -> Response {
    pf_send_response(run, handle, &PF_KILL, PfKillArgs { pid }).await
}

async fn pf_get_pid(run: &mut RunContext<'_>, handle: &AgentHandle) -> Response {
    pf_send_response(run, handle, &PF_GET_PID, ()).await
}

async fn pf_net_listen(run: &mut RunContext<'_>, handle: &AgentHandle, port: u16) -> Response {
    pf_send_response(run, handle, &PF_NET_LISTEN, PfNetListenArgs { port }).await
}

async fn pf_net_unlisten(run: &mut RunContext<'_>, handle: &AgentHandle, port: u16) -> Response {
    pf_send_response(run, handle, &PF_NET_UNLISTEN, PfNetListenArgs { port }).await
}

async fn pf_net_connect(
    run: &mut RunContext<'_>,
    handle: &AgentHandle,
    addr: String,
    data: String,
) -> Response {
    pf_send_response(
        run,
        handle,
        &PF_NET_CONNECT,
        PfNetConnectArgs { addr, data },
    )
    .await
}

async fn handle_pf_exec(
    args: PfExecArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<Response, HandlerError> {
    if args.args.is_empty() {
        return Ok(Response::Error {
            error: "exec requires args".to_string(),
        });
    }
    let mut cmd = tokio::process::Command::new(&args.args[0]);
    cmd.args(&args.args[1..]);
    for (key, value) in &args.env {
        cmd.env(key, value);
    }
    if args.stdin.is_some() {
        cmd.stdin(Stdio::piped());
    } else {
        cmd.stdin(Stdio::null());
    }
    if args.background {
        cmd.stdout(Stdio::null()).stderr(Stdio::null());
        match cmd.spawn() {
            Ok(mut child) => {
                if let Some(content) = args.stdin
                    && let Some(mut stdin) = child.stdin.take()
                {
                    let _ = stdin.write_all(content.as_bytes()).await;
                }
                Ok(Response::Background {
                    pid: child.id().unwrap_or(0),
                })
            }
            Err(e) => Ok(Response::Error {
                error: format!("exec spawn: {e}"),
            }),
        }
    } else {
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = match cmd.spawn() {
            Ok(child) => child,
            Err(e) => {
                return Ok(Response::Error {
                    error: format!("exec spawn: {e}"),
                });
            }
        };
        if let Some(content) = args.stdin
            && let Some(mut stdin) = child.stdin.take()
        {
            let _ = stdin.write_all(content.as_bytes()).await;
        }
        let timeout = Duration::from_secs(args.timeout_secs.unwrap_or(10));
        match tokio::time::timeout(timeout, child.wait_with_output()).await {
            Ok(Ok(output)) => Ok(Response::ExecResult {
                exit_code: output.status.code().unwrap_or(-1),
                stdout: String::from_utf8_lossy(&output.stdout).to_string(),
                stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            }),
            Ok(Err(e)) => Ok(Response::Error {
                error: format!("exec wait: {e}"),
            }),
            Err(_) => Ok(Response::ExecTimeout {
                stderr: format!(
                    "process timed out after {}s (likely deadlocked)",
                    timeout.as_secs()
                ),
            }),
        }
    }
}

#[allow(clippy::too_many_lines)]
async fn handle_pf_exec_ready(
    args: PfExecReadyArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<Response, HandlerError> {
    if args.args.is_empty() {
        return Ok(Response::Error {
            error: "exec_ready requires args".to_string(),
        });
    }
    if !matches!(args.stream.as_str(), "stdout" | "stderr" | "either") {
        return Ok(Response::Error {
            error: format!(
                "invalid marker stream {:?}; expected stdout, stderr, or either",
                args.stream
            ),
        });
    }
    let mut cmd = std::process::Command::new(&args.args[0]);
    cmd.args(&args.args[1..]);
    if args.stdin.is_some() {
        cmd.stdin(Stdio::piped());
    } else {
        cmd.stdin(Stdio::null());
    }
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => {
            return Ok(Response::Error {
                error: format!("exec_ready spawn: {e}"),
            });
        }
    };
    if let Some(content) = args.stdin
        && let Some(mut stdin) = child.stdin.take()
    {
        let _ = std::io::Write::write_all(&mut stdin, content.as_bytes());
    }
    let Some(stdout) = child.stdout.take() else {
        return Ok(Response::Error {
            error: "exec_ready: stdout pipe missing".to_string(),
        });
    };
    let Some(stderr) = child.stderr.take() else {
        return Ok(Response::Error {
            error: "exec_ready: stderr pipe missing".to_string(),
        });
    };
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    let marker = args.ready_marker.clone();
    let stream = args.stream.clone();
    if matches!(stream.as_str(), "stdout" | "either") {
        let tx = tx.clone();
        let marker = marker.clone();
        std::thread::spawn(move || {
            let mut reader = std::io::BufReader::new(stdout);
            let mut seen = Vec::new();
            let mut byte = [0_u8; 1];
            while let Ok(1) = std::io::Read::read(&mut reader, &mut byte) {
                seen.push(byte[0]);
                if String::from_utf8_lossy(&seen).contains(&marker) {
                    let _ = tx.send("ready".to_string());
                    break;
                }
            }
        });
    }
    if matches!(stream.as_str(), "stderr" | "either") {
        let tx = tx.clone();
        let marker = marker.clone();
        std::thread::spawn(move || {
            let mut reader = std::io::BufReader::new(stderr);
            let mut seen = Vec::new();
            let mut byte = [0_u8; 1];
            while let Ok(1) = std::io::Read::read(&mut reader, &mut byte) {
                seen.push(byte[0]);
                if String::from_utf8_lossy(&seen).contains(&marker) {
                    let _ = tx.send("ready".to_string());
                    break;
                }
            }
        });
    }
    let timeout = Duration::from_secs(args.timeout_secs.unwrap_or(30));
    let start = Instant::now();
    loop {
        if rx.try_recv().is_ok() {
            let pid = child.id();
            std::mem::forget(child);
            return Ok(Response::BackgroundReady { pid });
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                return Ok(Response::Error {
                    error: format!("process exited before ready_marker (status={status})"),
                });
            }
            Ok(None) => {}
            Err(e) => {
                return Ok(Response::Error {
                    error: format!("exec_ready poll: {e}"),
                });
            }
        }
        if start.elapsed() >= timeout {
            let _ = child.kill();
            return Ok(Response::Error {
                error: format!("ready_marker not observed within {}s", timeout.as_secs()),
            });
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

async fn handle_pf_fs_read(
    args: PfPathArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<Response, HandlerError> {
    match tokio::fs::read_to_string(&args.path).await {
        Ok(data) => Ok(Response::Ok { data: Some(data) }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Response::NotFound),
        Err(e) => Ok(Response::Error {
            error: format!("read {}: {e}", args.path),
        }),
    }
}

async fn handle_pf_fs_delete(
    args: PfPathArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<Response, HandlerError> {
    match tokio::fs::remove_file(&args.path).await {
        Ok(()) => Ok(Response::Ok { data: None }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Response::NotFound),
        Err(e) => Ok(Response::Error {
            error: format!("delete {}: {e}", args.path),
        }),
    }
}

async fn handle_pf_kill(
    args: PfKillArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<Response, HandlerError> {
    let Ok(pid) = libc::pid_t::try_from(args.pid) else {
        return Ok(Response::Error {
            error: format!("kill {}: pid out of range", args.pid),
        });
    };
    // SAFETY: libc::kill is called with a PID returned by a previous background spawn and a constant signal.
    let rc = unsafe { libc::kill(pid, libc::SIGKILL) };
    if rc == 0 {
        Ok(Response::Ok { data: None })
    } else {
        Ok(Response::Error {
            error: format!("kill {}: {}", args.pid, std::io::Error::last_os_error()),
        })
    }
}

async fn handle_pf_get_pid(_args: (), _ctx: &mut HandlerCtx<'_>) -> Result<Response, HandlerError> {
    Ok(Response::Ok {
        data: Some(std::process::id().to_string()),
    })
}

async fn handle_pf_net_listen(
    args: PfNetListenArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<Response, HandlerError> {
    // Bind with std::net so we can pull out the OwnedFd for the
    // inherit_bridge, then re-wrap as a tokio listener for the accept
    // task.
    let std_listener =
        match std::net::TcpListener::bind((std::net::Ipv4Addr::UNSPECIFIED, args.port)) {
            Ok(l) => l,
            Err(e) => {
                return Ok(Response::Error {
                    error: format!("bind {}: {e}", args.port),
                });
            }
        };
    let port = match std_listener.local_addr() {
        Ok(addr) => addr.port(),
        Err(e) => {
            return Ok(Response::Error {
                error: format!("local_addr: {e}"),
            });
        }
    };
    // Dup the fd so the bridge owns one copy (for Fork inheritance)
    // and the tokio listener owns the other (for the accept task).
    let raw = std::os::fd::AsRawFd::as_raw_fd(&std_listener);
    // SAFETY: F_DUPFD_CLOEXEC duplicates a valid open fd; ownership of the
    // returned descriptor is moved into OwnedFd::from_raw_fd below.
    let dup = unsafe { libc::fcntl(raw, libc::F_DUPFD_CLOEXEC, 3) };
    if dup < 0 {
        return Ok(Response::Error {
            error: format!("dup fd for bridge: {}", std::io::Error::last_os_error()),
        });
    }
    // SAFETY: `dup` was just returned by fcntl F_DUPFD_CLOEXEC.
    let bridge_owned = unsafe { std::os::fd::OwnedFd::from_raw_fd(dup) };
    if let Some(old) = crate::inherit_bridge()
        .lock()
        .expect("inherit bridge")
        .insert(port, bridge_owned)
    {
        drop(old);
    }
    let _ = std_listener.set_nonblocking(true);
    let listener = match tokio::net::TcpListener::from_std(std_listener) {
        Ok(l) => l,
        Err(e) => {
            return Ok(Response::Error {
                error: format!("from_std: {e}"),
            });
        }
    };
    let task = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0_u8; 4096];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if stream.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    if let Some(old) = pf_tcp_listeners()
        .lock()
        .expect("tcp listener registry poisoned")
        .insert(port, task)
    {
        old.abort();
    }
    Ok(Response::Listening { port })
}

async fn handle_pf_net_unlisten(
    args: PfNetListenArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<Response, HandlerError> {
    if let Some(task) = pf_tcp_listeners()
        .lock()
        .expect("tcp listener registry poisoned")
        .remove(&args.port)
    {
        task.abort();
    }
    crate::inherit_bridge()
        .lock()
        .expect("inherit bridge")
        .remove(&args.port);
    Ok(Response::Ok { data: None })
}

async fn handle_pf_net_connect(
    args: PfNetConnectArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<Response, HandlerError> {
    match tokio::time::timeout(
        Duration::from_secs(5),
        tokio::net::TcpStream::connect(&args.addr),
    )
    .await
    {
        Ok(Ok(mut stream)) => {
            let _ = stream.write_all(args.data.as_bytes()).await;
            let _ = stream.flush().await;
            let mut buf = [0_u8; 4096];
            match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => Ok(Response::Connected {
                    echo: String::from_utf8_lossy(&buf[..n]).to_string(),
                }),
                _ => Ok(Response::ConnectFailed {
                    error: "no echo response".to_string(),
                }),
            }
        }
        Ok(Err(e)) => Ok(Response::ConnectFailed {
            error: format!("{e}"),
        }),
        Err(_) => Ok(Response::ConnectFailed {
            error: "connect timeout".to_string(),
        }),
    }
}

fn register_platform_fix_handlers() {
    register_handler!(PF_EXEC, handle_pf_exec);
    register_handler!(PF_EXEC_READY, handle_pf_exec_ready);
    register_handler!(PF_FS_READ, handle_pf_fs_read);
    register_handler!(PF_FS_DELETE, handle_pf_fs_delete);
    register_handler!(PF_KILL, handle_pf_kill);
    register_handler!(PF_GET_PID, handle_pf_get_pid);
    register_handler!(PF_NET_LISTEN, handle_pf_net_listen);
    register_handler!(PF_NET_UNLISTEN, handle_pf_net_unlisten);
    register_handler!(PF_NET_CONNECT, handle_pf_net_connect);
    register_handler!(CLI_STARTUP_MIMIC, handle_cli_startup_mimic);
    register_handler!(FORK_EXEC_PIE, handle_fork_exec_pie);
    register_handler!(PIPE_NONBLOCK, handle_pipe_nonblock);
    register_handler!(PIPE_CHILD_NONBLOCK, handle_pipe_child_nonblock);
    register_handler!(EPOLL_SOCKET, handle_epoll_socket);
    register_handler!(CROSS_WORKER_FILE, handle_cross_worker_file);

    crate::register_leaf_subcommand!("cross-worker-file", leaf_subcmd::subcmd_cross_worker_file);
    crate::register_leaf_subcommand!("proc-probe", leaf_subcmd::subcmd_proc_probe);
    crate::register_leaf_subcommand!("check-ppid", leaf_subcmd::subcmd_check_ppid);
}

async fn handle_cli_startup_mimic(
    _args: CliStartupMimicArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<DetailOut, HandlerError> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| HandlerError::from(format!("bind cli startup mimic listener: {e}")))?;
    let addr = listener
        .local_addr()
        .map_err(|e| HandlerError::from(format!("listener addr: {e}")))?;
    Ok(DetailOut {
        detail: format!("CLI_STARTUP_MIMIC_OK {addr}"),
    })
}

async fn handle_fork_exec_pie(
    args: ForkExecPieArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<DetailOut, HandlerError> {
    let detail = (|| -> Result<String, String> {
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(format!("fork: {}", std::io::Error::last_os_error()));
        }
        if pid == 0 {
            let bin = std::ffi::CString::new(args.binary.as_str()).expect("binary has no NUL");
            let sub =
                std::ffi::CString::new(args.subcommand.as_str()).expect("subcommand has no NUL");
            let exec_argv = [bin.as_ptr(), sub.as_ptr(), core::ptr::null()];
            // SAFETY: child process passes valid NUL-terminated argv to execv; on failure it exits.
            unsafe { libc::execv(bin.as_ptr(), exec_argv.as_ptr()) };
            std::process::exit(127);
        }

        let deadline = Instant::now() + StdDuration::from_secs(15);
        let mut status = 0i32;
        loop {
            // SAFETY: pid is a live child pid from fork and status points to valid storage.
            let ret = unsafe { libc::waitpid(pid, &raw mut status, libc::WNOHANG) };
            if ret > 0 {
                if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 {
                    return Ok("FORK_EXEC_PIE_OK".into());
                }
                return Ok(format!("FORK_EXEC_PIE_FAIL:exit={status}"));
            }
            if Instant::now() >= deadline {
                // SAFETY: pid is the child process being timed out.
                unsafe { libc::kill(pid, libc::SIGKILL) };
                // SAFETY: reap the child after SIGKILL; null status is allowed.
                unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
                return Ok("FORK_EXEC_PIE_FAIL:timeout".into());
            }
            std::thread::sleep(StdDuration::from_millis(50));
        }
    })()?;
    Ok(DetailOut { detail })
}

async fn handle_pipe_nonblock(
    _args: PipeNonblockArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<DetailOut, HandlerError> {
    let detail = (|| -> Result<String, String> {
        let mut out = Vec::new();
        let mut fds = [0i32; 2];
        // SAFETY: pipe initializes two fds on success.
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
            return Err(format!("pipe: {}", std::io::Error::last_os_error()));
        }
        let read_fd = fds[0];
        let write_fd = fds[1];
        // SAFETY: read_fd is a valid pipe fd.
        let flags = unsafe { libc::fcntl(read_fd, libc::F_GETFL) };
        // SAFETY: read_fd is valid and flags are from F_GETFL.
        let ret = unsafe { libc::fcntl(read_fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
        out.push(format!(
            "PIPE_NB_SETFL={}",
            if ret == 0 { "OK" } else { "FAIL" }
        ));
        let mut buf = [0u8; 64];
        // SAFETY: read_fd is valid and buf is writable.
        let n = unsafe { libc::read(read_fd, buf.as_mut_ptr().cast(), buf.len()) };
        // SAFETY: errno is thread-local and read just failed or returned.
        let errno = unsafe { *libc::__errno_location() };
        if n == -1 && (errno == libc::EAGAIN || errno == libc::EWOULDBLOCK) {
            out.push("PIPE_NB_EMPTY=EAGAIN".into());
        } else {
            out.push(format!("PIPE_NB_EMPTY=UNEXPECTED n={n} errno={errno}"));
        }
        let msg = b"HELLO";
        // SAFETY: write_fd is valid and msg points to readable bytes.
        unsafe { libc::write(write_fd, msg.as_ptr().cast(), msg.len()) };
        // SAFETY: read_fd is valid and buf is writable.
        let n = unsafe { libc::read(read_fd, buf.as_mut_ptr().cast(), buf.len()) };
        out.push(if n == 5 {
            "PIPE_NB_DATA=OK".into()
        } else {
            format!("PIPE_NB_DATA=UNEXPECTED n={n}")
        });
        // SAFETY: write_fd is a valid fd and is no longer used after close.
        unsafe { libc::close(write_fd) };
        // SAFETY: read_fd is valid and buf is writable.
        let n = unsafe { libc::read(read_fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n == 0 {
            out.push("PIPE_NB_EOF=OK".into());
        } else {
            // SAFETY: errno is thread-local and read just returned unexpectedly.
            let errno = unsafe { *libc::__errno_location() };
            out.push(format!("PIPE_NB_EOF=UNEXPECTED n={n} errno={errno}"));
        }
        // SAFETY: read_fd is a valid fd and is no longer used after close.
        unsafe { libc::close(read_fd) };
        Ok(out.join("\n"))
    })()?;
    Ok(DetailOut { detail })
}

async fn handle_pipe_child_nonblock(
    _args: PipeChildNonblockArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<DetailOut, HandlerError> {
    let detail = (|| -> Result<String, String> {
        let mut out = Vec::new();
        let mut fds = [0i32; 2];
        // SAFETY: pipe initializes two fds on success.
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
            return Err(format!("pipe: {}", std::io::Error::last_os_error()));
        }
        let read_fd = fds[0];
        let write_fd = fds[1];
        // SAFETY: fork duplicates the current process; child exits below.
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            // SAFETY: child owns these fds after fork.
            unsafe { libc::close(read_fd) };
            std::thread::sleep(StdDuration::from_millis(500));
            let msg = b"X";
            // SAFETY: write_fd is valid and msg is readable.
            unsafe { libc::write(write_fd, msg.as_ptr().cast(), 1) };
            // SAFETY: child is done with write_fd.
            unsafe { libc::close(write_fd) };
            std::process::exit(0);
        }
        if pid < 0 {
            return Err(format!("fork: {}", std::io::Error::last_os_error()));
        }
        // SAFETY: parent is done with write_fd.
        unsafe { libc::close(write_fd) };
        // SAFETY: read_fd is a valid pipe fd.
        let flags = unsafe { libc::fcntl(read_fd, libc::F_GETFL) };
        // SAFETY: read_fd is valid and flags are from F_GETFL.
        unsafe { libc::fcntl(read_fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
        let mut buf = [0u8; 1];
        // SAFETY: read_fd is valid and buf is writable.
        let n = unsafe { libc::read(read_fd, buf.as_mut_ptr().cast(), 1) };
        // SAFETY: errno is thread-local and read just returned.
        let errno = unsafe { *libc::__errno_location() };
        if n == -1 && (errno == libc::EAGAIN || errno == libc::EWOULDBLOCK) {
            out.push("PCHILD_INITIAL=EAGAIN".into());
        } else {
            out.push(format!("PCHILD_INITIAL=UNEXPECTED n={n} errno={errno}"));
        }
        std::thread::sleep(StdDuration::from_secs(1));
        // SAFETY: read_fd is valid and buf is writable.
        let n = unsafe { libc::read(read_fd, buf.as_mut_ptr().cast(), 1) };
        if n == 1 {
            out.push("PCHILD_DATA=OK".into());
        } else {
            // SAFETY: errno is thread-local and read just returned unexpectedly.
            let errno = unsafe { *libc::__errno_location() };
            out.push(format!("PCHILD_DATA=UNEXPECTED n={n} errno={errno}"));
        }
        // SAFETY: read_fd is valid and buf is writable.
        let n = unsafe { libc::read(read_fd, buf.as_mut_ptr().cast(), 1) };
        if n == 0 {
            out.push("PCHILD_EOF=OK".into());
        } else {
            // SAFETY: errno is thread-local and read just returned unexpectedly.
            let errno = unsafe { *libc::__errno_location() };
            out.push(format!("PCHILD_EOF=UNEXPECTED n={n} errno={errno}"));
        }
        // SAFETY: cleanup live fd and reap the child pid.
        unsafe { libc::close(read_fd) };
        // SAFETY: pid is a child process from fork.
        unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
        Ok(out.join("\n"))
    })()?;
    Ok(DetailOut { detail })
}

async fn handle_epoll_socket(
    args: EpollSocketArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<DetailOut, HandlerError> {
    let detail = epoll_socket_detail(args.port, &args.variant)?;
    Ok(DetailOut { detail })
}

async fn handle_cross_worker_file(
    args: CrossWorkerFileArgs,
    ctx: &mut HandlerCtx<'_>,
) -> Result<DetailOut, HandlerError> {
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
    Ok(DetailOut {
        detail: "[cross-worker-file] READY".into(),
    })
}

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::too_many_lines
)]
fn epoll_socket_detail(port: u16, variant: &str) -> Result<String, HandlerError> {
    let mut out = Vec::new();
    // SAFETY: all raw sockets/fds created here are checked for errors and closed before return.
    unsafe {
        let srv = libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0);
        if srv < 0 {
            return Err(HandlerError::from(format!(
                "socket: {}",
                std::io::Error::last_os_error()
            )));
        }
        let one: libc::c_int = 1;
        libc::setsockopt(
            srv,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            (&raw const one).cast::<libc::c_void>(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        let addr = libc::sockaddr_in {
            sin_family: libc::AF_INET as u16,
            sin_port: port.to_be(),
            sin_addr: libc::in_addr { s_addr: 0 },
            sin_zero: [0; 8],
        };
        if libc::bind(
            srv,
            (&raw const addr).cast::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        ) != 0
        {
            let e = std::io::Error::last_os_error();
            libc::close(srv);
            return Err(HandlerError::from(format!("bind: {e}")));
        }
        libc::listen(srv, 5);
        let epfd = libc::epoll_create1(0);
        if epfd < 0 {
            let e = std::io::Error::last_os_error();
            libc::close(srv);
            return Err(HandlerError::from(format!("epoll_create1: {e}")));
        }
        let mut ev = libc::epoll_event {
            events: libc::EPOLLIN as u32,
            u64: srv as u64,
        };
        libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, srv, &raw mut ev);
        let client = std::thread::spawn(move || {
            std::thread::sleep(StdDuration::from_millis(500));
            let sock = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
            let addr = libc::sockaddr_in {
                sin_family: libc::AF_INET as u16,
                sin_port: port.to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_be_bytes([127, 0, 0, 1]).to_be(),
                },
                sin_zero: [0; 8],
            };
            libc::connect(
                sock,
                (&raw const addr).cast::<libc::sockaddr>(),
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            );
            let msg = b"EPOLL_DATA";
            libc::send(sock, msg.as_ptr().cast(), msg.len(), 0);
            libc::close(sock);
        });
        let mut events = [libc::epoll_event { events: 0, u64: 0 }; 4];
        if variant == "tokio" {
            let n = libc::epoll_wait(epfd, events.as_mut_ptr(), 4, 0);
            if n > 0 {
                out.push("EPOLL_ACCEPT=IMMEDIATE".into());
            } else {
                let n = libc::epoll_wait(epfd, events.as_mut_ptr(), 4, 5000);
                if n <= 0 {
                    out.push("EPOLL_ACCEPT=TIMEOUT".into());
                    let _ = client.join();
                    libc::close(srv);
                    libc::close(epfd);
                    return Ok(out.join("\n"));
                }
                out.push("EPOLL_ACCEPT=WOKE".into());
            }
        } else {
            let n = libc::epoll_wait(epfd, events.as_mut_ptr(), 4, 5000);
            if n <= 0 {
                out.push("EPOLL_ACCEPT=TIMEOUT".into());
                let _ = client.join();
                libc::close(srv);
                libc::close(epfd);
                return Ok(out.join("\n"));
            }
            out.push("EPOLL_ACCEPT=READY".into());
        }
        let conn = libc::accept4(
            srv,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            libc::SOCK_NONBLOCK,
        );
        if conn < 0 {
            out.push("EPOLL_ACCEPT=FAIL".into());
        } else {
            let mut ev2 = libc::epoll_event {
                events: libc::EPOLLIN as u32,
                u64: conn as u64,
            };
            libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, conn, &raw mut ev2);
            let n2 = libc::epoll_wait(epfd, events.as_mut_ptr(), 4, 5000);
            if n2 <= 0 {
                out.push("EPOLL_READ=TIMEOUT".into());
            } else {
                let mut buf = [0u8; 64];
                let nr = libc::recv(conn, buf.as_mut_ptr().cast(), buf.len(), 0);
                if nr > 0 {
                    let data = std::str::from_utf8(&buf[..nr.cast_unsigned()]).unwrap_or("?");
                    out.push(format!("EPOLL_READ=OK data={data}"));
                } else {
                    out.push(format!("EPOLL_READ=NO_DATA nr={nr}"));
                }
            }
            libc::close(conn);
        }
        let _ = client.join();
        libc::close(srv);
        libc::close(epfd);
    }
    Ok(out.join("\n"))
}

fn fork_binary_label(bt: crate::BinaryType) -> &'static str {
    match bt {
        crate::BinaryType::PieGlibc => "self",
        crate::BinaryType::NonPieGlibc => "nonpie",
        crate::BinaryType::StaticPieGlibc => "static-pie-glibc",
        crate::BinaryType::StaticPieMusl => "static-pie-musl",
        crate::BinaryType::NonPieStaticMusl => "non-pie-static-musl",
    }
}

mod leaf_subcmd {
    use std::io::Write;

    pub(super) fn subcmd_cross_worker_file(args: &[String]) -> i32 {
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

    pub(super) fn subcmd_check_ppid(_args: &[String]) -> i32 {
        let ppid = unsafe { libc::getppid() };
        let proc_exists = std::path::Path::new(&format!("/proc/{ppid}")).exists();
        let kill_ret = unsafe { libc::kill(ppid, 0) };
        let kill_errno = if kill_ret != 0 {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
        } else {
            0
        };
        let kill_ok = kill_ret == 0;
        println!("ppid={ppid} proc={proc_exists} kill0={kill_ok} errno={kill_errno}");
        0
    }

    pub(super) fn subcmd_proc_probe(args: &[String]) -> i32 {
        let pid = unsafe { libc::getpid() };
        let parent_pid = unsafe { libc::getppid() };
        let self_exists = std::path::Path::new("/proc/self").exists();
        let self_cmdline = std::fs::read_to_string("/proc/self/cmdline")
            .map(|s| !s.is_empty())
            .unwrap_or(false);
        let self_stat = std::fs::read_to_string("/proc/self/stat")
            .map(|s| !s.is_empty())
            .unwrap_or(false);
        let own_proc = std::path::Path::new(&format!("/proc/{pid}")).exists();
        let own_cmdline = std::fs::read_to_string(format!("/proc/{pid}/cmdline"))
            .map(|s| !s.is_empty())
            .unwrap_or(false);
        let ppid_proc = std::path::Path::new(&format!("/proc/{parent_pid}")).exists();
        let ppid_cmdline = std::fs::read_to_string(format!("/proc/{parent_pid}/cmdline"))
            .map(|s| !s.is_empty())
            .unwrap_or(false);
        let ppid_kill0_ret = unsafe { libc::kill(parent_pid, 0) };
        let ppid_kill0_errno = if ppid_kill0_ret != 0 {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
        } else {
            0
        };
        let ppid_kill0 = ppid_kill0_ret == 0;
        print!("pid={pid} ppid={parent_pid}");
        print!(" self={self_exists} self_cmdline={self_cmdline} self_stat={self_stat}");
        print!(" own_proc={own_proc} own_cmdline={own_cmdline}");
        print!(
            " ppid_proc={ppid_proc} ppid_cmdline={ppid_cmdline} ppid_kill0={ppid_kill0} ppid_kill0_errno={ppid_kill0_errno}"
        );
        if let Some(target) = args.get(2).and_then(|s| s.parse::<i32>().ok()) {
            let t_proc = std::path::Path::new(&format!("/proc/{target}")).exists();
            let t_kill0 = unsafe { libc::kill(target, 0) } == 0;
            print!(" target={target} target_proc={t_proc} target_kill0={t_kill0}");
        }
        println!();
        0
    }
}

async fn handle_poll_ready(
    args: PollReadyArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<DetailOut, HandlerError> {
    let detail = (|| -> Result<String, String> {
        let mut pipe_fds = [0i32; 2];
        // SAFETY: pipe writes two fresh fds into pipe_fds on success.
        if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } != 0 {
            return Err(format!("pipe: {}", std::io::Error::last_os_error()));
        }
        let (read_fd, write_fd) = (pipe_fds[0], pipe_fds[1]);
        let data = b"poll_test_data";
        // SAFETY: write_fd is a live pipe fd and data points to readable bytes.
        let _ = unsafe { libc::write(write_fd, data.as_ptr().cast(), data.len()) };
        let mut fds = [libc::pollfd {
            fd: read_fd,
            events: libc::POLLIN,
            revents: 0,
        }];
        // SAFETY: fds points to one valid pollfd.
        let n = unsafe {
            libc::poll(
                fds.as_mut_ptr(),
                1,
                i32::try_from(args.timeout_ms).unwrap_or(i32::MAX),
            )
        };
        // SAFETY: both fds are owned by this handler.
        unsafe {
            libc::close(write_fd);
            libc::close(read_fd);
        }
        if n > 0 && (fds[0].revents & libc::POLLIN) != 0 {
            Ok("POLLIN".to_string())
        } else {
            Ok("TIMEOUT".to_string())
        }
    })()?;
    Ok(DetailOut { detail })
}

async fn handle_bind_getsockname(
    args: BindGetsocknameArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<DetailOut, HandlerError> {
    let port = match args.family.as_str() {
        "ipv4" => std::net::TcpListener::bind("0.0.0.0:0")?
            .local_addr()?
            .port(),
        "ipv6" => std::net::TcpListener::bind("[::]:0")?.local_addr()?.port(),
        other => return Err(HandlerError(format!("unknown family: {other}"))),
    };
    Ok(DetailOut {
        detail: format!("port={port}"),
    })
}

async fn handle_pipe_pair_id(
    args: PipePairIdArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<DetailOut, HandlerError> {
    use std::collections::HashSet;
    let mut first_batch = HashSet::new();
    let mut fds = Vec::new();
    for _ in 0..args.count {
        let mut pipe_fds = [0i32; 2];
        // SAFETY: pipe writes two fresh fds into pipe_fds on success.
        if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } != 0 {
            return Err(HandlerError(format!(
                "pipe: {}",
                std::io::Error::last_os_error()
            )));
        }
        // SAFETY: zeroed stat is a valid output buffer for fstat.
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: pipe_fds[0] is a live fd and stat is writable.
        if unsafe { libc::fstat(pipe_fds[0], &raw mut stat) } == 0 {
            first_batch.insert(stat.st_ino);
        }
        fds.push(pipe_fds);
    }
    for pipe_fds in fds.drain(..) {
        // SAFETY: fds were created by this handler and are still owned here.
        unsafe {
            libc::close(pipe_fds[0]);
            libc::close(pipe_fds[1]);
        }
    }
    let mut collisions = 0u32;
    for _ in 0..args.count {
        let mut pipe_fds = [0i32; 2];
        // SAFETY: pipe writes two fresh fds into pipe_fds on success.
        if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } != 0 {
            return Err(HandlerError(format!(
                "pipe: {}",
                std::io::Error::last_os_error()
            )));
        }
        // SAFETY: zeroed stat is a valid output buffer for fstat.
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: pipe_fds[0] is a live fd and stat is writable.
        if unsafe { libc::fstat(pipe_fds[0], &raw mut stat) } == 0
            && first_batch.contains(&stat.st_ino)
        {
            collisions += 1;
        }
        // SAFETY: fds were created by this handler and are still owned here.
        unsafe {
            libc::close(pipe_fds[0]);
            libc::close(pipe_fds[1]);
        }
    }
    if collisions == 0 {
        Ok(DetailOut {
            detail: "unique".to_string(),
        })
    } else {
        Err(HandlerError(format!(
            "collision: {collisions}/{} ids reused",
            args.count
        )))
    }
}

async fn handle_accept_inherited(
    args: AcceptInheritedArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<DetailOut, HandlerError> {
    let spec = std::env::var("LITEBOX_TEST_HARNESS_INHERITED_LISTEN_FDS")
        .map_err(|e| HandlerError(format!("missing inherited listener env: {e}")))?;
    let fd = spec
        .split(',')
        .find_map(|item| {
            let (port_s, fd_s) = item.split_once('=')?;
            if port_s.parse::<u16>().ok()? == args.port {
                fd_s.parse::<i32>().ok()
            } else {
                None
            }
        })
        .ok_or_else(|| {
            HandlerError(format!(
                "no inherited fd for port {} in {spec:?}",
                args.port
            ))
        })?;
    let timeout = StdDuration::from_secs(args.timeout_secs);
    std::thread::spawn(move || {
        // SAFETY: agent import publishes a handler-owned duplicate fd in the
        // inheritance env mapping. This thread takes ownership of that fd.
        let listener = unsafe { std::net::TcpListener::from_raw_fd(fd) };
        let _ = listener.set_nonblocking(false);
        if let Ok((mut stream, _)) = listener.accept() {
            let _ = stream.set_read_timeout(Some(timeout));
            let _ = stream.set_write_timeout(Some(timeout));
            let mut buf = [0u8; 4096];
            loop {
                match std::io::Read::read(&mut stream, &mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if std::io::Write::write_all(&mut stream, &buf[..n]).is_err() {
                            break;
                        }
                    }
                }
            }
        }
    });
    Ok(DetailOut {
        detail: format!("accepting on port {}", args.port),
    })
}

#[derive(Deserialize, Serialize)]
struct ClosePortArgs {
    port: u16,
}

const CLOSE_INHERITED: HandlerToken<ClosePortArgs, DetailOut> =
    HandlerToken::new("platform_fixes.close_inherited");

async fn handle_close_inherited(
    args: ClosePortArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<DetailOut, HandlerError> {
    let spec = std::env::var("LITEBOX_TEST_HARNESS_INHERITED_LISTEN_FDS")
        .map_err(|e| HandlerError(format!("missing inherited listener env: {e}")))?;
    let fd = spec
        .split(',')
        .find_map(|item| {
            let (port_s, fd_s) = item.split_once('=')?;
            if port_s.parse::<u16>().ok()? == args.port {
                fd_s.parse::<i32>().ok()
            } else {
                None
            }
        })
        .ok_or_else(|| {
            HandlerError(format!(
                "no inherited fd for port {} in {spec:?}",
                args.port
            ))
        })?;
    // SAFETY: closing an inherited listener fd published by the agent;
    // takes ownership via OwnedFd so the drop closes it exactly once.
    let _owned = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
    Ok(DetailOut {
        detail: format!("closed inherited listener fd for port {}", args.port),
    })
}

// Constants used by the register_* functions further down. Each test
// category gets a section divider immediately above its `register_*`
// function (POLL, GSN, PID, EXITD, NPIPE, …).

const FAMILIES: &[&str] = &["ipv4", "ipv6"];

const EXIT_SIZES: &[usize] = &[256, 4096, 65536];

const NPIPE_REPS: &[usize] = &[1, 5, 10];
// Pipe-bridge churn ("npipe") fan-out parents. Each entry is a
// long-lived agent the test runs in; the agent's binary type
// determines which parent-side bridge / pipe-host code path is
// exercised. Including the static legs covers the cli (StaticPieMusl)
// and node-class scenarios as forking parents.
const NPIPE_AGENTS: &[AgentName] = &[
    AgentName::Dpg1,       // PIE-glibc
    AgentName::Dpg1Dpg1,   // PIE-glibc, depth-2
    AgentName::Dpg2,       // PIE-glibc, sibling subtree
    AgentName::Dpg1Dng,    // non-PIE-glibc (node form)
    AgentName::Dpg1DngDng, // bash → bash recursion (VS Code hot path)
    AgentName::Dpg1DngSpm, // bash → cli (VS Code hot path)
    AgentName::Dpg1Spg,    // static-PIE-glibc (still uses ld.so)
    AgentName::Dpg1Spm,    // static-PIE-musl (no ld.so) — cli form
    AgentName::Dpg1SpmDng, // cli → node (VS Code's signature transition)
    AgentName::Dpg1Snm,    // non-PIE-static-musl
];

// ═══════════════════════════════════════════════════════════════════
// POLL: epoll/ppoll IN events (fix 0fb258e2)
// ═══════════════════════════════════════════════════════════════════

pub(crate) fn register_poll_ready_tests(reg: &mut Registry<'_>) {
    register_handler!(POLL_READY, handle_poll_ready);
    for &agent in AGENTS {
        let agent_s = agent.to_string();
        reg.test("matrix", "poll_ready", format!("POLL.pipe.{agent}"))
            .timeout(60)
            .build(move |cx| {
                let handle = cx.require(agent);
                Box::new(move |run| {
                    let a = agent_s.clone();
                    Box::pin(async move {
                        let result = run
                            .send_named_typed(
                                &handle,
                                &POLL_READY,
                                PollReadyArgs { timeout_ms: 2000 },
                            )
                            .await;
                        let pass = matches!(&result, Ok(out) if out.detail == "POLLIN");
                        super::TestOutcome::new(&a, pass, format!("{result:?}"))
                    })
                })
            });
    }
}

// ═══════════════════════════════════════════════════════════════════
// GSN: getsockname port after bind (fix 336dc79e)
// ═══════════════════════════════════════════════════════════════════

pub(crate) fn register_bind_getsockname_tests(reg: &mut Registry<'_>) {
    register_handler!(BIND_GETSOCKNAME, handle_bind_getsockname);
    for &family in FAMILIES {
        for &agent in DEPTH_AGENTS {
            let agent_s = agent.to_string();
            let family_s = family.to_string();
            reg.test(
                "matrix",
                "bind_getsockname",
                format!("GSN.{family}.{agent}"),
            )
            .timeout(60)
            .build(move |cx| {
                let handle = cx.require(agent);
                Box::new(move |run| {
                    let a = agent_s.clone();
                    let f = family_s.clone();
                    Box::pin(async move {
                        let result = run
                            .send_named_typed(
                                &handle,
                                &BIND_GETSOCKNAME,
                                BindGetsocknameArgs { family: f },
                            )
                            .await;
                        let pass = match &result {
                            Ok(out) => out
                                .detail
                                .strip_prefix("port=")
                                .and_then(|s| s.parse::<u16>().ok())
                                .is_some_and(|p| p > 0),
                            Err(_) => false,
                        };
                        super::TestOutcome::new(&a, pass, format!("{result:?}"))
                    })
                })
            });
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// PID: monotonic pipe pair_id (fix c2d0abdc)
// ═══════════════════════════════════════════════════════════════════

pub(crate) fn register_pipe_pair_id_tests(reg: &mut Registry<'_>) {
    register_handler!(PIPE_PAIR_ID, handle_pipe_pair_id);
    for &agent in AGENTS {
        let agent_s = agent.to_string();
        reg.test("matrix", "pipe_pair_id", format!("PID.{agent}"))
            .timeout(60)
            .build(move |cx| {
                let handle = cx.require(agent);
                Box::new(move |run| {
                    let a = agent_s.clone();
                    Box::pin(async move {
                        let result = run
                            .send_named_typed(&handle, &PIPE_PAIR_ID, PipePairIdArgs { count: 100 })
                            .await;
                        let pass = matches!(&result, Ok(out) if out.detail == "unique");
                        super::TestOutcome::new(&a, pass, format!("{result:?}"))
                    })
                })
            });
    }
}

// ═══════════════════════════════════════════════════════════════════
// EXITD: bridge thread join before exit (fix 2def3ac6)
// ═══════════════════════════════════════════════════════════════════

pub(crate) fn register_exit_data_integrity_tests(reg: &mut Registry<'_>) {
    register_platform_fix_handlers();
    for &size in EXIT_SIZES {
        for &binary in crate::BinaryType::ALL {
            for &agent in DEPTH_AGENTS {
                let agent_s = agent.to_string();
                let binary_label = binary.label();
                reg.test(
                    "fork",
                    "exit_data_integrity",
                    format!("EXITD.{size}.{binary_label}.{agent}"),
                )
                .timeout(60)
                .build(move |cx| {
                    let leaf = cx.declare_ephemeral(
                        agent,
                        format!("ExitData_{size}_{binary_label}_{agent}"),
                        SpawnKind::Fork {
                            binary: fork_binary_label(binary),
                            inherit_listen_ports: vec![],
                        },
                    );
                    Box::new(move |run| {
                        let a = agent_s.clone();
                        Box::pin(async move {
                            let result = run
                                .run_leaf(
                                    &leaf,
                                    &super::common::WRITE_THEN_EXIT,
                                    super::common::WriteThenExitArgs { size },
                                )
                                .await;
                            let pass = matches!(&result, Ok(out) if out.data.len() == size);
                            let detail = match &result {
                                Ok(out) => format!("got {} bytes, expected {size}", out.data.len()),
                                Err(e) => e.clone(),
                            };
                            super::TestOutcome::new(&a, pass, detail)
                        })
                    })
                });
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// NPIPE: non-PIE pipe chain integrity (fix febc3e41)
// ═══════════════════════════════════════════════════════════════════

#[allow(clippy::too_many_lines)] // exhaustive registration / runner
pub(crate) fn register_nonpie_pipe_chain_tests(reg: &mut Registry<'_>) {
    register_platform_fix_handlers();
    for &reps in NPIPE_REPS {
        for &agent in NPIPE_AGENTS {
            let agent_s = agent.to_string();
            // Sequential non-PIE pattern.
            reg.test(
                "fork",
                "nonpie_pipe_chain",
                format!("NPIPE.seq.x{reps}.{agent}"),
            )
            .timeout(60)
            .build(move |cx| {
                let handle = cx.require(agent);
                Box::new(move |run| {
                    let a = agent_s.clone();
                    let _self_exe = run.self_exe().to_string();
                    Box::pin(async move {
                        let nonpie = crate::nonpie_binary();
                        let mut all_clean = true;
                        let mut detail = String::new();
                        for i in 0..reps {
                            let tag = format!("seq_{a}_{i}");
                            let resp = pf_exec(
                                run,
                                &handle,
                                vec![nonpie.clone(), "write-known".into(), tag.clone()],
                            )
                            .await;
                            let expected = format!("PIPEDATA:{tag}");
                            let ok = matches!(
                                &resp,
                                Response::ExecResult { exit_code: 0, stdout, .. }
                                    if stdout.trim() == expected
                            );
                            if !ok {
                                all_clean = false;
                                detail = format!("iter {i}: expected '{expected}', got {resp:?}");
                                break;
                            }
                        }
                        if all_clean {
                            detail = format!("{reps} sequential non-PIE execs all clean");
                        }
                        super::TestOutcome::new(&a, all_clean, detail)
                    })
                })
            });

            // Interleaved PIE + non-PIE pattern.
            let agent_s2 = agent.to_string();
            reg.test(
                "fork",
                "nonpie_pipe_chain",
                format!("NPIPE.interleaved.x{reps}.{agent}"),
            )
            .timeout(60)
            .build(move |cx| {
                let handle = cx.require(agent);
                Box::new(move |run| {
                    let a = agent_s2.clone();
                    let self_exe = run.self_exe().to_string();
                    Box::pin(async move {
                        let nonpie = crate::nonpie_binary();
                        let mut all_clean = true;
                        let mut detail = String::new();
                        for i in 0..reps {
                            let np_tag = format!("np_{a}_{i}");
                            let resp = pf_exec(
                                run,
                                &handle,
                                vec![nonpie.clone(), "write-known".into(), np_tag.clone()],
                            )
                            .await;
                            let expected = format!("PIPEDATA:{np_tag}");
                            let ok = matches!(
                                &resp,
                                Response::ExecResult { exit_code: 0, stdout, .. }
                                    if stdout.trim() == expected
                            );
                            if !ok {
                                all_clean = false;
                                detail =
                                    format!("iter {i} nonpie: expected '{expected}', got {resp:?}");
                                break;
                            }
                            let resp =
                                pf_exec(run, &handle, vec![self_exe.clone(), "echo-test".into()])
                                    .await;
                            let ok = matches!(
                                &resp,
                                Response::ExecResult { exit_code: 0, stdout, .. }
                                    if stdout.trim() == "ECHO_TEST_OK"
                            );
                            if !ok {
                                all_clean = false;
                                detail =
                                    format!("iter {i} pie: expected 'ECHO_TEST_OK', got {resp:?}");
                                break;
                            }
                        }
                        if all_clean {
                            detail = format!("{reps} interleaved PIE+nonPIE execs all clean");
                        }
                        super::TestOutcome::new(&a, all_clean, detail)
                    })
                })
            });
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// BPIPE: per-binary-type pipe chain integrity (extends NPIPE)
//
// NPIPE above covers the non-PIE-glibc leg as a singleton matrix.
// BPIPE expands the same patterns (sequential and interleaved
// fork+execs whose stdout flows through a pipe to the parent) to the
// other four legs of `BinaryType` so the platform's pipe-chain
// integrity is exercised across every binary mode the shim might
// dispatch differently:
//
//   BPIPE.{pie-glibc,static-pie-glibc,
//          static-pie-musl,non-pie-static-musl}
//        .{seq,interleaved}
//        .x{reps}
//        .{A,AA}
//
// `interleaved` alternates the under-test leg with the always-PIE-glibc
// `self_exe` so the test catches pollution between legs.
// ═══════════════════════════════════════════════════════════════════

#[allow(clippy::too_many_lines)] // exhaustive registration / runner
pub(crate) fn register_bpipe_tests(reg: &mut Registry<'_>) {
    register_platform_fix_handlers();
    // Exercise every binary type with uniform per-leg IDs.
    for &bt in crate::BinaryType::ALL {
        let leg_label = bt.label();
        for &reps in NPIPE_REPS {
            for &agent in DEPTH_AGENTS {
                let agent_s = agent.to_string();
                reg.test(
                    "fork",
                    "bpipe",
                    format!("BPIPE.{leg_label}.seq.x{reps}.{agent}"),
                )
                .timeout(60)
                .build(move |cx| {
                    let handle = cx.require(agent);
                    Box::new(move |run| {
                        let a = agent_s.clone();
                        let self_exe = run.self_exe().to_string();
                        Box::pin(async move {
                            let target = crate::binary_path(bt, &self_exe);
                            let mut all_clean = true;
                            let mut detail = String::new();
                            for i in 0..reps {
                                let tag = format!("seq_{leg_label}_{a}_{i}");
                                let resp = pf_exec(
                                    run,
                                    &handle,
                                    vec![target.clone(), "write-known".into(), tag.clone()],
                                )
                                .await;
                                let expected = format!("PIPEDATA:{tag}");
                                let ok = matches!(
                                    &resp,
                                    Response::ExecResult { exit_code: 0, stdout, .. }
                                        if stdout.trim() == expected
                                );
                                if !ok {
                                    all_clean = false;
                                    detail =
                                        format!("iter {i}: expected '{expected}', got {resp:?}");
                                    break;
                                }
                            }
                            if all_clean {
                                detail = format!("{reps} sequential {leg_label} execs all clean");
                            }
                            super::TestOutcome::new(&a, all_clean, detail)
                        })
                    })
                });

                let agent_s2 = agent.to_string();
                reg.test(
                    "fork",
                    "bpipe",
                    format!("BPIPE.{leg_label}.interleaved.x{reps}.{agent}"),
                )
                .timeout(60)
                .build(move |cx| {
                    let handle = cx.require(agent);
                    Box::new(move |run| {
                        let a = agent_s2.clone();
                        let self_exe = run.self_exe().to_string();
                        Box::pin(async move {
                            let target = crate::binary_path(bt, &self_exe);
                            let mut all_clean = true;
                            let mut detail = String::new();
                            for i in 0..reps {
                                let tag = format!("itr_{leg_label}_{a}_{i}");
                                let resp = pf_exec(
                                    run,
                                    &handle,
                                    vec![target.clone(), "write-known".into(), tag.clone()],
                                )
                                .await;
                                let expected = format!("PIPEDATA:{tag}");
                                let ok = matches!(
                                    &resp,
                                    Response::ExecResult { exit_code: 0, stdout, .. }
                                        if stdout.trim() == expected
                                );
                                if !ok {
                                    all_clean = false;
                                    detail = format!(
                                        "iter {i} {leg_label}: expected '{expected}', got {resp:?}"
                                    );
                                    break;
                                }
                                let resp = pf_exec(
                                    run,
                                    &handle,
                                    vec![self_exe.clone(), "echo-test".into()],
                                )
                                .await;
                                let ok = matches!(
                                    &resp,
                                    Response::ExecResult { exit_code: 0, stdout, .. }
                                        if stdout.trim() == "ECHO_TEST_OK"
                                );
                                if !ok {
                                    all_clean = false;
                                    detail = format!(
                                        "iter {i} pie-glibc: expected 'ECHO_TEST_OK', got {resp:?}"
                                    );
                                    break;
                                }
                            }
                            if all_clean {
                                detail = format!(
                                    "{reps} interleaved {leg_label}+pie-glibc execs all clean"
                                );
                            }
                            super::TestOutcome::new(&a, all_clean, detail)
                        })
                    })
                });
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// XCONN: cross-worker TCP — first connection must succeed
// ═══════════════════════════════════════════════════════════════════

#[allow(clippy::too_many_lines)] // exhaustive registration / runner
pub(crate) fn register_cross_worker_first_connect_tests(reg: &mut Registry<'_>) {
    register_platform_fix_handlers();
    // XCONN.cross_first: A listens, B connects — first attempt must succeed.
    reg.test(
        "xworker",
        "cross_worker_first_connect",
        "XCONN.cross_first".to_string(),
    )
    .timeout(60)
    .build(move |cx| {
        let handle_a = cx.require(AgentName::Dpg1);
        let handle_b = cx.require(AgentName::Dpg2);
        Box::new(move |run| {
            Box::pin(async move {
                let port = 19900u16;
                let listen_resp = pf_net_listen(run, &handle_a, port).await;
                if super::expect_listening_port(&listen_resp, port).is_err() {
                    return super::TestOutcome::new(
                        "B",
                        false,
                        format!("listen failed: {listen_resp:?}"),
                    );
                }
                let conn_resp = pf_net_connect(
                    run,
                    &handle_b,
                    format!("127.0.0.1:{port}"),
                    "first_connect".into(),
                )
                .await;
                let ok =
                    matches!(&conn_resp, Response::Connected { echo } if echo == "first_connect");
                let _ = pf_net_unlisten(run, &handle_a, port).await;
                super::TestOutcome::new("B", ok, format!("{conn_resp:?}"))
            })
        })
    });
    // XCONN.deep_cross: B listens, AA (deeper worker) connects.
    reg.test(
        "xworker",
        "cross_worker_first_connect",
        "XCONN.deep_cross".to_string(),
    )
    .timeout(60)
    .build(move |cx| {
        let handle_aa = cx.require(AgentName::Dpg1Dpg1);
        let handle_b = cx.require(AgentName::Dpg2);
        Box::new(move |run| {
            Box::pin(async move {
                let port = 19901u16;
                let listen_resp = pf_net_listen(run, &handle_b, port).await;
                if super::expect_listening_port(&listen_resp, port).is_err() {
                    return super::TestOutcome::new(
                        "AA",
                        false,
                        format!("listen on B failed: {listen_resp:?}"),
                    );
                }
                let conn_resp = pf_net_connect(
                    run,
                    &handle_aa,
                    format!("127.0.0.1:{port}"),
                    "deep_cross".into(),
                )
                .await;
                let ok = matches!(&conn_resp, Response::Connected { echo } if echo == "deep_cross");
                let _ = pf_net_unlisten(run, &handle_b, port).await;
                super::TestOutcome::new("AA", ok, format!("{conn_resp:?}"))
            })
        })
    });
    // XCONN.cross_seq_x3: 3 rapid sequential connections from B to A's listener.
    reg.test("xworker", "cross_worker_first_connect", "XCONN.cross_seq_x3".to_string())
    .timeout(60)
    .build(move |cx| {
        let handle_a = cx.require(AgentName::Dpg1);
        let handle_b = cx.require(AgentName::Dpg2);
        Box::new(move |run| {
                Box::pin(async move {
                    let port = 19902u16;
                    let listen_resp = pf_net_listen(run, &handle_a, port).await;
                    if super::expect_listening_port(&listen_resp, port).is_err() {
                        return super::TestOutcome::new(
                            "B",
                            false,
                            format!("listen failed: {listen_resp:?}"),
                        );
                    }
                    let mut all_ok = true;
                    let mut fail_detail = String::new();
                    for i in 0..3 {
                        let conn_resp = pf_net_connect(run, &handle_b, format!("127.0.0.1:{port}"), format!("seq_{i}")).await;
                        if !matches!(&conn_resp, Response::Connected { echo } if echo == &format!("seq_{i}"))
                        {
                            all_ok = false;
                            fail_detail = format!("connection {i} failed: {conn_resp:?}");
                            break;
                        }
                    }
                    let _ = pf_net_unlisten(run, &handle_a, port).await;
                    let detail = if all_ok {
                        "3/3 sequential OK".into()
                    } else {
                        fail_detail
                    };
                    super::TestOutcome::new("B", all_ok, detail)
                })
        })
    });
}

// ═══════════════════════════════════════════════════════════════════
// XCONN.self: same-worker loopback (VS Code pattern)
// ═══════════════════════════════════════════════════════════════════

#[allow(clippy::too_many_lines)] // exhaustive registration / runner
pub(crate) fn register_cross_worker_self_connect_tests(reg: &mut Registry<'_>) {
    register_platform_fix_handlers();
    // XCONN.self_A: A listens, A connects to itself.
    reg.test(
        "xworker",
        "cross_worker_self_connect",
        "XCONN.self_A".to_string(),
    )
    .timeout(60)
    .build(move |cx| {
        let handle_a = cx.require(AgentName::Dpg1);
        Box::new(move |run| {
            Box::pin(async move {
                let port = 19910u16;
                let listen_resp = pf_net_listen(run, &handle_a, port).await;
                if super::expect_listening_port(&listen_resp, port).is_err() {
                    return super::TestOutcome::new(
                        "A",
                        false,
                        format!("listen failed: {listen_resp:?}"),
                    );
                }
                let conn_resp = pf_net_connect(
                    run,
                    &handle_a,
                    format!("127.0.0.1:{port}"),
                    "self_loopback".into(),
                )
                .await;
                let ok =
                    matches!(&conn_resp, Response::Connected { echo } if echo == "self_loopback");
                let _ = pf_net_unlisten(run, &handle_a, port).await;
                super::TestOutcome::new("A", ok, format!("{conn_resp:?}"))
            })
        })
    });
    // XCONN.parent_child: A listens, AA connects.
    reg.test(
        "xworker",
        "cross_worker_self_connect",
        "XCONN.parent_child".to_string(),
    )
    .timeout(60)
    .build(move |cx| {
        let handle_a = cx.require(AgentName::Dpg1);
        let handle_aa = cx.require(AgentName::Dpg1Dpg1);
        Box::new(move |run| {
            Box::pin(async move {
                let port = 19911u16;
                let listen_resp = pf_net_listen(run, &handle_a, port).await;
                if super::expect_listening_port(&listen_resp, port).is_err() {
                    return super::TestOutcome::new(
                        "AA",
                        false,
                        format!("listen failed: {listen_resp:?}"),
                    );
                }
                let conn_resp = pf_net_connect(
                    run,
                    &handle_aa,
                    format!("127.0.0.1:{port}"),
                    "parent_child".into(),
                )
                .await;
                let ok =
                    matches!(&conn_resp, Response::Connected { echo } if echo == "parent_child");
                let _ = pf_net_unlisten(run, &handle_a, port).await;
                super::TestOutcome::new("AA", ok, format!("{conn_resp:?}"))
            })
        })
    });
    // XCONN.child_parent: AA listens, A connects.
    reg.test(
        "xworker",
        "cross_worker_self_connect",
        "XCONN.child_parent".to_string(),
    )
    .timeout(60)
    .build(move |cx| {
        let handle_a = cx.require(AgentName::Dpg1);
        let handle_aa = cx.require(AgentName::Dpg1Dpg1);
        Box::new(move |run| {
            Box::pin(async move {
                let port = 19912u16;
                let listen_resp = pf_net_listen(run, &handle_aa, port).await;
                if super::expect_listening_port(&listen_resp, port).is_err() {
                    return super::TestOutcome::new(
                        "A",
                        false,
                        format!("listen failed: {listen_resp:?}"),
                    );
                }
                let conn_resp = pf_net_connect(
                    run,
                    &handle_a,
                    format!("127.0.0.1:{port}"),
                    "child_parent".into(),
                )
                .await;
                let ok =
                    matches!(&conn_resp, Response::Connected { echo } if echo == "child_parent");
                let _ = pf_net_unlisten(run, &handle_aa, port).await;
                super::TestOutcome::new("A", ok, format!("{conn_resp:?}"))
            })
        })
    });
    // XCONN.sibling_AB: A listens, AB connects.
    reg.test(
        "xworker",
        "cross_worker_self_connect",
        "XCONN.sibling_AB".to_string(),
    )
    .timeout(60)
    .build(move |cx| {
        let handle_a = cx.require(AgentName::Dpg1);
        let handle_ab = cx.require(AgentName::Dpg1Dpg2);
        Box::new(move |run| {
            Box::pin(async move {
                let port = 19913u16;
                let listen_resp = pf_net_listen(run, &handle_a, port).await;
                if super::expect_listening_port(&listen_resp, port).is_err() {
                    return super::TestOutcome::new(
                        "AB",
                        false,
                        format!("listen failed: {listen_resp:?}"),
                    );
                }
                let conn_resp = pf_net_connect(
                    run,
                    &handle_ab,
                    format!("127.0.0.1:{port}"),
                    "sibling_connect".into(),
                )
                .await;
                let ok =
                    matches!(&conn_resp, Response::Connected { echo } if echo == "sibling_connect");
                let _ = pf_net_unlisten(run, &handle_a, port).await;
                super::TestOutcome::new("AB", ok, format!("{conn_resp:?}"))
            })
        })
    });
}

// ═══════════════════════════════════════════════════════════════════
// TLB: TCP listen remains usable after delayed accept window
// ═══════════════════════════════════════════════════════════════════

const TLB_DELAY_SECS: u64 = 1;

struct TlbListenBusyDef {
    name: &'static str,
    listener: AgentName,
    connector: AgentName,
}

async fn run_tlb_listen_busy_case(
    run: &mut RunContext<'_>,
    listener: &AgentHandle,
    connector: &AgentHandle,
    listener_name: &str,
    connector_name: &str,
    data: &str,
    delay_secs: u64,
) -> super::TestOutcome {
    let listen_resp = pf_net_listen(run, listener, 0).await;
    let port = match super::expect_listening_port(&listen_resp, 0) {
        Ok(port) => port,
        Err(e) => {
            return super::TestOutcome::new(
                connector_name,
                false,
                format!("{listener_name} listen failed: {e}; resp={listen_resp:?}"),
            );
        }
    };

    let sleep_resp = pf_exec_full(
        run,
        listener,
        vec!["sleep".into(), delay_secs.to_string()],
        Some(delay_secs + 5),
        None,
        vec![],
    )
    .await;
    if !matches!(&sleep_resp, Response::ExecResult { exit_code: 0, .. }) {
        let _ = pf_net_unlisten(run, listener, port).await;
        return super::TestOutcome::new(
            connector_name,
            false,
            format!("{listener_name} delay failed: {sleep_resp:?}"),
        );
    }

    let conn_resp = pf_net_connect(
        run,
        connector,
        format!("127.0.0.1:{port}"),
        data.to_string(),
    )
    .await;
    let _ = pf_net_unlisten(run, listener, port).await;
    let pass = matches!(&conn_resp, Response::Connected { echo } if echo == data);
    super::TestOutcome::new(
        connector_name,
        pass,
        format!(
            "listener={listener_name} connector={connector_name} delay={delay_secs}s {conn_resp:?}"
        ),
    )
}

pub(crate) fn register_tcp_listen_busy_tests(reg: &mut Registry<'_>) {
    register_platform_fix_handlers();
    let defs = [
        TlbListenBusyDef {
            name: "same_agent",
            listener: AgentName::Dpg1,
            connector: AgentName::Dpg1,
        },
        TlbListenBusyDef {
            name: "parent_child",
            listener: AgentName::Dpg1,
            connector: AgentName::Dpg1Dpg1,
        },
        TlbListenBusyDef {
            name: "child_parent",
            listener: AgentName::Dpg1Dpg1,
            connector: AgentName::Dpg1,
        },
        TlbListenBusyDef {
            name: "sibling",
            listener: AgentName::Dpg1Dpg1,
            connector: AgentName::Dpg1Dpg2,
        },
        TlbListenBusyDef {
            name: "depth2",
            listener: AgentName::Dpg1Dpg1Dpg1,
            connector: AgentName::Dpg1Dpg1Dpg2,
        },
    ];

    for def in defs {
        let listener_name = def.listener.to_string();
        let connector_name = def.connector.to_string();
        let data = format!("TLB_{}", def.name);
        reg.test(
            "xworker",
            "tcp_listen_busy",
            format!("TLB.listen_busy.{}", def.name),
        )
        .timeout(60)
        .build(move |cx| {
            let listener = cx.require(def.listener);
            let connector = cx.require(def.connector);
            Box::new(move |run| {
                let listener_name = listener_name.clone();
                let connector_name = connector_name.clone();
                let data = data.clone();
                Box::pin(async move {
                    run_tlb_listen_busy_case(
                        run,
                        &listener,
                        &connector,
                        &listener_name,
                        &connector_name,
                        &data,
                        TLB_DELAY_SECS,
                    )
                    .await
                })
            })
        });
    }
}

// ═══════════════════════════════════════════════════════════════════
// BASH: bash fork+exec of child commands
// ═══════════════════════════════════════════════════════════════════

pub(crate) fn register_bash_fork_exec_tests(reg: &mut Registry<'_>) {
    register_platform_fix_handlers();
    for &agent in &[AgentName::Dpg1, AgentName::Dpg2] {
        let agent_s = agent.to_string();

        // BASH.fork_ls: bash -c running ls
        let a = agent_s.clone();
        reg.test("fork", "bash_fork_exec", format!("BASH.fork_ls.{agent}"))
            .timeout(60)
            .build(move |cx| {
                let handle = cx.require(agent);
                Box::new(move |run| {
                    let a = a.clone();
                    Box::pin(async move {
                        let resp = pf_exec(
                            run,
                            &handle,
                            vec![
                                "bash".into(),
                                "-c".into(),
                                "ls / > /dev/null && echo LS_OK".into(),
                            ],
                        )
                        .await;
                        let pass = matches!(
                            &resp,
                            Response::ExecResult { exit_code: 0, stdout, .. }
                                if stdout.contains("LS_OK")
                        );
                        super::TestOutcome::new(&a, pass, format!("{resp:?}"))
                    })
                })
            });

        // BASH.fork_subst: bash -c with command substitution
        let a = agent_s.clone();
        reg.test("fork", "bash_fork_exec", format!("BASH.fork_subst.{agent}"))
            .timeout(60)
            .build(move |cx| {
                let handle = cx.require(agent);
                Box::new(move |run| {
                    let a = a.clone();
                    Box::pin(async move {
                        let resp = pf_exec(
                            run,
                            &handle,
                            vec![
                                "bash".into(),
                                "-c".into(),
                                "echo HOST=$(cat /etc/hostname)".into(),
                            ],
                        )
                        .await;
                        // Substituted hostname must be non-empty (the substitution
                        // actually ran). `hostname -I` worked above on the same
                        // container, so /etc/hostname is non-empty.
                        let pass = matches!(
                            &resp,
                            Response::ExecResult { exit_code: 0, stdout, .. }
                                if stdout.starts_with("HOST=")
                                    && stdout.trim_end().len() > "HOST=".len()
                        );
                        super::TestOutcome::new(&a, pass, format!("{resp:?}"))
                    })
                })
            });

        // BASH.fork_bg_fg: bash -c with background + foreground
        let a = agent_s.clone();
        reg.test("fork", "bash_fork_exec", format!("BASH.fork_bg_fg.{agent}"))
            .timeout(60)
            .build(move |cx| {
                let handle = cx.require(agent);
                Box::new(move |run| {
                    let a = a.clone();
                    Box::pin(async move {
                        let resp = pf_exec(
                            run,
                            &handle,
                            vec![
                                "bash".into(),
                                "-c".into(),
                                // The bg subshell must actually run and emit
                                // BG_DONE; the fg leg must run too. Wait for
                                // bg before printing FG_DONE so output
                                // ordering is deterministic.
                                "(sleep 0.05 && echo BG_DONE) & \
                                     cat /etc/hostname > /dev/null; \
                                     wait; \
                                     echo FG_DONE"
                                    .into(),
                            ],
                        )
                        .await;
                        let pass = matches!(
                            &resp,
                            Response::ExecResult { exit_code: 0, stdout, .. }
                                if stdout.contains("BG_DONE") && stdout.contains("FG_DONE")
                        );
                        super::TestOutcome::new(&a, pass, format!("{resp:?}"))
                    })
                })
            });
    }
}

// ═══════════════════════════════════════════════════════════════════
// FWE: fork+exec from non-PIE worker-exec hosts
// ═══════════════════════════════════════════════════════════════════

#[allow(clippy::too_many_lines)] // exhaustive registration / runner
pub(crate) fn register_fork_from_worker_exec_tests(reg: &mut Registry<'_>) {
    register_platform_fix_handlers();
    // FWE matrix:
    //   - launcher = init   (agent A, PIE) ─► fork+execv each BinaryType
    //   - launcher = NP     (worker-exec host, non-PIE) ─► same
    //
    // Both arms use the fork-exec-pie handler (which is plain
    // fork+execv with no PIE-specific logic; the historical name is
    // kept for backwards compatibility). The binary executed is
    // resolved per `BinaryType` via `binary_path()`.
    //
    for &bt in crate::BinaryType::ALL {
        for (launcher_label, launcher_agent) in [
            ("from_init", AgentName::Dpg1),
            ("from_worker_exec", AgentName::Dpg1Dng),
        ] {
            let bt_label = bt.label();
            let test_id = format!("FWE.{bt_label}.{launcher_label}");
            let outcome_label = format!("{launcher_agent}");
            reg.test("fork", "fork_from_worker_exec", test_id.clone())
                .timeout(60)
                .build(move |cx| {
                    let launcher_binary = match launcher_agent {
                        AgentName::Dpg1 => "self",
                        AgentName::Dpg1Dng => "nonpie",
                        _ => unreachable!(),
                    };
                    let leaf = cx.declare_ephemeral(
                        launcher_agent,
                        format!("ForkExecPie_{bt_label}_{launcher_label}"),
                        SpawnKind::Fork {
                            binary: launcher_binary,
                            inherit_listen_ports: vec![],
                        },
                    );
                    Box::new(move |run| {
                        let outcome_label = outcome_label.clone();
                        let self_exe = run.self_exe().to_string();
                        Box::pin(async move {
                            let target = crate::binary_path(bt, &self_exe);
                            let result = run
                                .run_leaf(
                                    &leaf,
                                    &FORK_EXEC_PIE,
                                    ForkExecPieArgs {
                                        binary: target,
                                        subcommand: "echo-test".into(),
                                    },
                                )
                                .await;
                            let pass = matches!(&result, Ok(out) if out.detail.contains("FORK_EXEC_PIE_OK"));
                            super::TestOutcome::new(&outcome_label, pass, format!("{result:?}"))
                        })
                    })
                });
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// M1-M4: Minimal canary repros for SpawnRemote/non-PIE bug
// ═══════════════════════════════════════════════════════════════════
//
// These are the minimal repros for the wave-0 canary cascade. The
// canary itself runs `Exec [self_exe, "echo-test"]` on agent A. It
// times out under litebox not because echo-test is broken, but
// because spawn_tree's earlier SpawnRemote NP call killed agent A
// as a side effect.
//
// Each M test runs as `Exec [self_exe, "M{N}-..."]` from a launcher
// agent. The M subprocess then spawns a non-PIE child via the
// indicated mechanism and verifies the parent process is still
// alive after wait. If the parent dies before printing M{N}_OK,
// the launcher's Exec times out or returns a bad exit code, and
// the test FAILs.
//
// Matrix: 4 M variants × 5 launchers (A, AA, D3, D4, D5):
//   - A, AA, D3, D5 are PIE — they exec a PIE M-subprocess. The
//     canary mechanism (PIE process tokio runtime spawning non-PIE
//     child) is reproduced inside the M subprocess.
//   - D4 is non-PIE — it execs a non-PIE M-subprocess. This tests
//     the related non-PIE → non-PIE spawn path.
//
// Native must pass all 20 tests.

pub(crate) fn register_minimal_canary_tests(reg: &mut Registry<'_>) {
    register_platform_fix_handlers();
    // Register the M1-M4 + BS1-BS3 leaf subcommands. These stay as
    // argv subcommands (not handlers) because they test fresh-process
    // stdio inheritance across fork+exec; see
    // `coordinator/platform_fixes_leaf_subcmd.rs` for the rationale.
    use crate::coordinator::platform_fixes_leaf_subcmd as m;
    crate::register_leaf_subcommand!("M1-tokio-spawn-nonpie", m::subcmd_m1_tokio_spawn_nonpie);
    crate::register_leaf_subcommand!("M2-libc-spawn-nonpie", m::subcmd_m2_libc_spawn_nonpie);
    crate::register_leaf_subcommand!(
        "M3-tokio-spawn-nonpie-then-work",
        m::subcmd_m3_tokio_spawn_nonpie_then_work
    );
    crate::register_leaf_subcommand!(
        "M4-tokio-spawn-nonpie-repeated",
        m::subcmd_m4_tokio_spawn_nonpie_repeated
    );
    crate::register_leaf_subcommand!(
        "BS1-tokio-spawn-nonpie-stderr",
        m::subcmd_bs1_tokio_spawn_nonpie_stderr
    );
    crate::register_leaf_subcommand!(
        "BS2-tokio-spawn-nonpie-stdin-echo",
        m::subcmd_bs2_tokio_spawn_nonpie_stdin_echo
    );
    crate::register_leaf_subcommand!(
        "BS3-tokio-spawn-nonpie-large-stdout",
        m::subcmd_bs3_tokio_spawn_nonpie_large_stdout
    );

    const M_LAUNCHERS: &[AgentName] = &[
        AgentName::Dpg1,
        AgentName::Dpg1Dpg1,
        AgentName::Dpg1Dpg1Dpg1,
        AgentName::Dpg1Dng,
        AgentName::Dpg1DngDpg,
    ];
    const M_VARIANTS: &[(&str, &str, &str, u64)] = &[
        // (id_prefix, subcommand, expected_stdout_marker, exec_timeout_secs)
        ("M1", "M1-tokio-spawn-nonpie", "M1_OK", 30),
        ("M2", "M2-libc-spawn-nonpie", "M2_OK", 30),
        ("M3", "M3-tokio-spawn-nonpie-then-work", "M3_OK", 30),
        ("M4", "M4-tokio-spawn-nonpie-repeated", "M4_OK", 60),
        // BS-variants: minimal stdio-direction repros for Bug B.
        // Same matrix shape as M1-M4. See main.rs comments for what
        // each subcommand exercises.
        ("BS1", "BS1-tokio-spawn-nonpie-stderr", "BS1_OK", 30),
        ("BS2", "BS2-tokio-spawn-nonpie-stdin-echo", "BS2_OK", 30),
        ("BS3", "BS3-tokio-spawn-nonpie-large-stdout", "BS3_OK", 30),
    ];

    for &launcher in M_LAUNCHERS {
        for &(id_prefix, subcommand, marker, timeout_secs) in M_VARIANTS {
            for &target_bt in crate::BinaryType::ALL {
                let launcher_s = launcher.to_string();
                let subcommand_s: String = subcommand.into();
                let marker_s: String = marker.into();
                let target_label = target_bt.label();
                let test_id = format!("{id_prefix}.{launcher_s}.{target_label}");
                reg.test("fork", "minimal_canary", test_id)
                    .timeout(timeout_secs + 10)
                    .build(move |cx| {
                        let handle = cx.require(launcher);
                        Box::new(move |run| {
                            let l = launcher_s.clone();
                            let sc = subcommand_s.clone();
                            let m = marker_s.clone();
                            let self_exe = run.self_exe().to_string();
                            Box::pin(async move {
                                let target = crate::binary_path(target_bt, &self_exe);
                                // Inject the target binary path into
                                // the M/BS subcommand via the
                                // `LITEBOX_M_TARGET_BINARY` env var.
                                let resp = pf_exec_full(
                                    run,
                                    &handle,
                                    vec![self_exe, sc],
                                    Some(timeout_secs),
                                    None,
                                    vec![("LITEBOX_M_TARGET_BINARY".into(), target)],
                                )
                                .await;
                                let pass = matches!(
                                    &resp,
                                    Response::ExecResult { exit_code: 0, stdout, .. }
                                        if stdout.contains(m.as_str())
                                );
                                super::TestOutcome::new(&l, pass, format!("{resp:?}"))
                            })
                        })
                    });
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// SP: stdin-pipe command substitution
// ═══════════════════════════════════════════════════════════════════

pub(crate) fn register_stdin_pipe_subst_tests(reg: &mut Registry<'_>) {
    register_platform_fix_handlers();
    struct Def {
        name: &'static str,
        script: &'static str,
        expected: &'static str,
    }
    let defs: &[Def] = &[
        Def {
            name: "simple",
            script: "X=$(echo hello)\necho R=$X\n",
            expected: "R=hello",
        },
        Def {
            name: "pipeline",
            script: "X=$(echo hello | cat)\necho R=$X\n",
            expected: "R=hello",
        },
        Def {
            name: "file_read",
            script: "X=$(head -1 /etc/passwd)\necho R=${X%%:*}\n",
            expected: "R=root",
        },
        Def {
            name: "file_pipe",
            script: "X=$(cat /etc/passwd | head -1)\necho R=${X%%:*}\n",
            expected: "R=root",
        },
        Def {
            name: "multi_subst",
            script: "A=$(echo first)\nB=$(echo second)\necho R=$A.$B\n",
            expected: "R=first.second",
        },
        Def {
            name: "os_detect",
            script: "ARCH=$(uname -m)\nPLATFORM=$(uname -s)\necho R=$ARCH.$PLATFORM\n",
            expected: "R=x86_64.Linux",
        },
    ];
    for &agent in AGENTS {
        for def in defs {
            let agent_s = agent.to_string();
            let script: String = def.script.into();
            let expected: String = def.expected.into();
            let name = def.name;
            reg.test("shell", "stdin_pipe_subst", format!("SP.{name}.{agent}"))
                .timeout(60)
                .build(move |cx| {
                    let handle = cx.require(agent);
                    Box::new(move |run| {
                        let a = agent_s.clone();
                        let s = script.clone();
                        let exp = expected.clone();
                        Box::pin(async move {
                            let resp = pf_exec_full(
                                run,
                                &handle,
                                vec!["/bin/sh".into()],
                                Some(15),
                                Some(s),
                                vec![],
                            )
                            .await;
                            let pass = matches!(
                                &resp,
                                Response::ExecResult { stdout, .. }
                                    if stdout.trim() == exp
                            );
                            super::TestOutcome::new(&a, pass, format!("{resp:?}"))
                        })
                    })
                });
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// CWF: Cross-worker file coherence
// ═══════════════════════════════════════════════════════════════════

#[allow(clippy::too_many_lines)] // exhaustive registration / runner
pub(crate) fn register_cross_worker_file_tests(reg: &mut Registry<'_>) {
    register_platform_fix_handlers();
    for &agent in AGENTS {
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
                                return super::TestOutcome::new(&a, false, e);
                            }
                            let resp = pf_fs_read(run, &handle, path.clone()).await;
                            let pass = matches!(
                                &resp,
                                Response::Ok { data: Some(d) } if d.starts_with("line0")
                            );
                            super::TestOutcome::new(&a, pass, format!("{resp:?}"))
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
                            return super::TestOutcome::new(&a, false, e);
                        }
                        if let Err(e) = run
                            .run_leaf_read_checkpoint(&leaf, "cross-worker-file-ready")
                            .await
                        {
                            return super::TestOutcome::new(&a, false, e);
                        }
                        let resp = pf_fs_read(run, &handle, path.clone()).await;
                        let pass = matches!(
                            &resp,
                            Response::Ok { data: Some(d) } if d.starts_with("line0")
                        );
                        let _ = run.run_leaf_resume(&leaf, "cross-worker-file-ready").await;
                        let _ = run.run_leaf_read_result(&leaf, &CROSS_WORKER_FILE).await;
                        let _ = run.run_leaf_exit(&leaf).await;
                        super::TestOutcome::new(&a, pass, format!("{resp:?}"))
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
                                return super::TestOutcome::new(&a, false, e);
                            }
                            if let Err(e) = run
                                .run_leaf_read_checkpoint(&leaf, "cross-worker-file-ready")
                                .await
                            {
                                return super::TestOutcome::new(&a, false, e);
                            }
                            let resp = pf_fs_read(run, &handle, path.clone()).await;
                            let pass = matches!(
                                &resp,
                                Response::Ok { data: Some(d) } if d.starts_with("line0")
                            );
                            let _ = run.run_leaf_resume(&leaf, "cross-worker-file-ready").await;
                            let _ = run.run_leaf_read_result(&leaf, &CROSS_WORKER_FILE).await;
                            let _ = run.run_leaf_exit(&leaf).await;
                            super::TestOutcome::new(&a, pass, format!("{resp:?}"))
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
                        let _ = pf_fs_delete(run, &handle, path.clone()).await;
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
                            return super::TestOutcome::new(&a, false, e);
                        }
                        if let Err(e) = run
                            .run_leaf_read_checkpoint(&leaf, "cross-worker-file-ready")
                            .await
                        {
                            return super::TestOutcome::new(&a, false, e);
                        }
                        let resp = pf_fs_read(run, &handle, path.clone()).await;
                        let pass = matches!(
                            &resp,
                            Response::Ok { data: Some(d) } if d.starts_with("line0")
                        );
                        let _ = run.run_leaf_resume(&leaf, "cross-worker-file-ready").await;
                        let _ = run.run_leaf_read_result(&leaf, &CROSS_WORKER_FILE).await;
                        let _ = run.run_leaf_exit(&leaf).await;
                        super::TestOutcome::new(&a, pass, format!("{resp:?}"))
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
                        let resp = pf_exec_ready(
                            run,
                            &handle,
                            vec!["bash".into(), "-c".into(), script],
                            "[cross-worker-file] READY".into(),
                            Some(15),
                            None,
                            "stderr".into(),
                        )
                        .await;
                        let pid = match &resp {
                            Response::BackgroundReady { pid } => Some(*pid),
                            _ => {
                                return super::TestOutcome::new(
                                    &a,
                                    false,
                                    format!("bg spawn failed: {resp:?}"),
                                );
                            }
                        };
                        let resp = pf_fs_read(run, &handle, path.clone()).await;
                        let pass = matches!(
                            &resp,
                            Response::Ok { data: Some(d) } if d.contains("line0")
                        );
                        if let Some(pid) = pid {
                            let _ = pf_kill(run, &handle, pid).await;
                        }
                        super::TestOutcome::new(&a, pass, format!("{resp:?}"))
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
                        let resp = pf_exec_full(
                            run,
                            &handle,
                            vec!["bash".into(), "-c".into(), script],
                            Some(15),
                            None,
                            vec![],
                        )
                        .await;
                        let pass = matches!(
                            &resp,
                            Response::ExecResult { stdout, .. }
                                if stdout.contains("ECHO_TEST_OK")
                        );
                        super::TestOutcome::new(&a, pass, format!("{resp:?}"))
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
                        let resp = pf_exec_full(
                            run,
                            &handle,
                            vec!["bash".into(), "-c".into(), script],
                            Some(10),
                            None,
                            vec![],
                        )
                        .await;
                        let pass = matches!(
                            &resp,
                            Response::ExecResult { stdout, .. }
                                if stdout.contains("builtin-data")
                        );
                        super::TestOutcome::new(&a, pass, format!("{resp:?}"))
                    })
                })
            });
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// SC: $() command substitution capture
// ═══════════════════════════════════════════════════════════════════

pub(crate) fn register_subst_capture_tests(reg: &mut Registry<'_>) {
    register_platform_fix_handlers();
    struct Def {
        name: &'static str,
        script: &'static str,
        check: fn(&str) -> bool,
    }
    let defs: &[Def] = &[
        Def {
            name: "echo",
            script: "X=$(echo hello); echo $X",
            check: |s| s.trim() == "hello",
        },
        Def {
            name: "cat",
            script: "X=$(cat /etc/hostname); echo $X",
            check: |s| !s.trim().is_empty(),
        },
        Def {
            name: "readlink",
            script: "X=$(readlink -f /usr/bin/bash); echo $X",
            check: |s| s.trim().contains("bash"),
        },
        Def {
            name: "dirname",
            script: "X=$(dirname /usr/bin/bash); echo $X",
            check: |s| s.trim() == "/usr/bin",
        },
        Def {
            name: "nested",
            script: "X=$(dirname $(readlink -f /usr/bin/bash)); echo $X",
            check: |s| !s.trim().is_empty() && s.trim() != "/",
        },
        Def {
            name: "vscode_root",
            script: concat!(
                "SCRIPT=$(which bash); ",
                "ROOT=$(dirname $(dirname $(readlink -f $SCRIPT))); ",
                "echo $ROOT",
            ),
            check: |s| !s.trim().is_empty() && s.trim() != "/" && s.trim() != "",
        },
        Def {
            name: "which",
            script: "X=$(which bash); echo $X",
            check: |s| s.trim().contains("bash"),
        },
        Def {
            name: "uname",
            script: "X=$(uname -m); echo $X",
            check: |s| s.trim() == "x86_64",
        },
    ];
    for &agent in AGENTS {
        for def in defs {
            let agent_s = agent.to_string();
            let script: String = def.script.into();
            let check = def.check;
            let name = def.name;
            reg.test("shell", "subst_capture", format!("SC.{name}.{agent}"))
                .timeout(60)
                .build(move |cx| {
                    let handle = cx.require(agent);
                    Box::new(move |run| {
                        let a = agent_s.clone();
                        let s = script.clone();
                        Box::pin(async move {
                            let resp = pf_exec_full(
                                run,
                                &handle,
                                vec!["bash".into(), "-c".into(), s],
                                Some(10),
                                None,
                                vec![],
                            )
                            .await;
                            let pass = matches!(
                                &resp,
                                Response::ExecResult { stdout, .. }
                                    if check(stdout)
                            );
                            super::TestOutcome::new(&a, pass, format!("{resp:?}"))
                        })
                    })
                });
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// CC: Concurrent fork/exec/pipe tests
// ═══════════════════════════════════════════════════════════════════

pub(crate) fn register_concurrent_fork_tests(reg: &mut Registry<'_>) {
    register_platform_fix_handlers();
    struct Def {
        name: &'static str,
        script_template: &'static str,
        check: fn(&str) -> bool,
    }
    let defs: &[Def] = &[
        Def {
            name: "echo",
            script_template: "echo $(echo hello) > {path}",
            check: |s| s.trim() == "hello",
        },
        Def {
            name: "fork_exec",
            script_template: "{exe} echo-test > {path} 2>&1",
            check: |s| s.contains("ECHO_TEST_OK"),
        },
        Def {
            name: "pipe_capture",
            script_template: "echo $(echo data | cat) > {path}",
            check: |s| s.trim() == "data",
        },
        Def {
            name: "file_write",
            script_template: "echo agent-wrote-{agent} > {path}",
            check: |s| s.contains("agent-wrote-"),
        },
    ];
    for def in defs {
        for &agent in AGENTS {
            let agent_s = agent.to_string();
            let template: String = def.script_template.into();
            let check = def.check;
            let name = def.name;
            reg.test("fork", "concurrent_fork", format!("CC.{name}.{agent}"))
                .timeout(60)
                .build(move |cx| {
                    let handle = cx.require(agent);
                    Box::new(move |run| {
                        let a = agent_s.clone();
                        let t = template.clone();
                        let self_exe = run.self_exe().to_string();
                        Box::pin(async move {
                            let path = format!("/shared/cc-{name}-{a}.txt");
                            let script = t
                                .replace("{path}", &path)
                                .replace("{exe}", &self_exe)
                                .replace("{agent}", &a);
                            let resp = pf_exec_full(
                                run,
                                &handle,
                                vec!["bash".into(), "-c".into(), script],
                                Some(10),
                                None,
                                vec![],
                            )
                            .await;
                            if !matches!(&resp, Response::ExecResult { exit_code: 0, .. }) {
                                return super::TestOutcome::new(
                                    &a,
                                    false,
                                    format!("writer failed: {resp:?}"),
                                );
                            }
                            let resp = pf_fs_read(run, &handle, path.clone()).await;
                            let pass = matches!(
                                &resp,
                                Response::Ok { data: Some(d) } if check(d)
                            );
                            super::TestOutcome::new(&a, pass, format!("{resp:?}"))
                        })
                    })
                });
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// TR: Touch + redirect file coherence
// ═══════════════════════════════════════════════════════════════════

pub(crate) fn register_touch_redirect_tests(reg: &mut Registry<'_>) {
    register_platform_fix_handlers();
    struct Def {
        name: &'static str,
        script_template: &'static str,
        check: fn(&str) -> bool,
    }
    let defs: &[Def] = &[
        Def {
            name: "no_touch",
            script_template: concat!(
                "rm -f {path}; ",
                "{exe} echo-test > {path} 2>&1\n",
                "cat {path}\n",
            ),
            check: |s| s.contains("ECHO_TEST_OK"),
        },
        Def {
            name: "touch",
            script_template: concat!(
                "rm -f {path}; touch {path}; ",
                "{exe} echo-test > {path} 2>&1\n",
                "cat {path}\n",
            ),
            check: |s| s.contains("ECHO_TEST_OK"),
        },
        Def {
            name: "touch_chmod",
            script_template: concat!(
                "rm -f {path}; touch {path}; chmod 600 {path}; ",
                "{exe} echo-test > {path} 2>&1\n",
                "cat {path}\n",
            ),
            check: |s| s.contains("ECHO_TEST_OK"),
        },
        Def {
            name: "echo_touch",
            script_template: concat!(
                "rm -f {path}; echo init > {path}; ",
                "{exe} echo-test > {path} 2>&1\n",
                "cat {path}\n",
            ),
            check: |s| s.contains("ECHO_TEST_OK"),
        },
        Def {
            name: "builtin_touch",
            script_template: concat!(
                "rm -f {path}; touch {path}; chmod 600 {path}; ",
                "echo builtin-data > {path} &\n",
                "wait\ncat {path}\n",
            ),
            check: |s| s.contains("builtin-data"),
        },
    ];
    for &agent in AGENTS {
        for def in defs {
            let agent_s = agent.to_string();
            let template: String = def.script_template.into();
            let check = def.check;
            let name = def.name;
            reg.test("shell", "touch_redirect", format!("TR.{name}.{agent}"))
                .timeout(60)
                .build(move |cx| {
                    let handle = cx.require(agent);
                    Box::new(move |run| {
                        let a = agent_s.clone();
                        let t = template.clone();
                        let self_exe = run.self_exe().to_string();
                        Box::pin(async move {
                            let path = format!("/shared/tr-{name}-{a}.txt");
                            let script = t.replace("{path}", &path).replace("{exe}", &self_exe);
                            let resp = pf_exec_full(
                                run,
                                &handle,
                                vec!["bash".into(), "-c".into(), script],
                                Some(10),
                                None,
                                vec![],
                            )
                            .await;
                            let pass = matches!(
                                &resp,
                                Response::ExecResult { stdout, .. }
                                    if check(stdout)
                            );
                            super::TestOutcome::new(&a, pass, format!("{resp:?}"))
                        })
                    })
                });
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// KP: PID and /proc visibility across delayed-fork migration
// ═══════════════════════════════════════════════════════════════════

#[allow(clippy::too_many_lines)] // exhaustive registration / runner
pub(crate) fn register_pid_visibility_tests(reg: &mut Registry<'_>) {
    register_platform_fix_handlers();
    struct Def {
        name: &'static str,
        script_template: &'static str,
        check: fn(&str) -> bool,
    }
    let defs: &[Def] = &[
        Def {
            name: "kill0_bg",
            script_template: concat!(
                "sleep 30 > /dev/null 2>&1 &\n",
                "PID=$!\n",
                "kill -0 $PID 2>/dev/null && echo KILL0_OK || echo KILL0_FAIL\n",
                "kill $PID 2>/dev/null; wait $PID 2>/dev/null\n",
            ),
            check: |s| s.contains("KILL0_OK"),
        },
        Def {
            name: "kill0_many",
            script_template: concat!(
                "A=$(cat /etc/os-release | head -1)\n",
                "B=$(uname -m)\n",
                "C=$(ls /tmp | head -1)\n",
                "D=$(echo x | cat)\n",
                "sleep 2 > /dev/null 2>&1 &\n",
                "PID=$!\n",
                "kill -0 $PID 2>/dev/null && echo KILL0_OK || echo KILL0_FAIL\n",
                "sleep 1\n",
                "kill -0 $PID 2>/dev/null && echo KILL0_1s_OK || echo KILL0_1s_FAIL\n",
                "wait $PID 2>/dev/null\n",
            ),
            check: |s| s.contains("KILL0_OK") && s.contains("KILL0_1s_OK"),
        },
        Def {
            name: "proc_child",
            script_template: concat!(
                "{exe} cross-worker-file write-and-hold /shared/kp-proc-child.txt > /dev/null 2>&1 &\n",
                "PID=$!\n",
                "until cat /proc/$PID/cmdline 2>/dev/null | tr '\\0' ' ' | grep -q litebox_test_harness; do :; done\n",
                "test -d /proc/$PID && echo PROC_DIR_OK || echo PROC_DIR_FAIL\n",
                "cat /proc/$PID/cmdline 2>/dev/null | tr '\\0' ' ' | ",
                "grep -q litebox_test_harness && echo CMDLINE_OK || echo CMDLINE_FAIL\n",
                "kill $PID 2>/dev/null; wait $PID 2>/dev/null\n",
            ),
            check: |s| s.contains("PROC_DIR_OK") && s.contains("CMDLINE_OK"),
        },
        Def {
            name: "proc_self",
            script_template: concat!(
                "{exe} proc-probe > /tmp/proc-self.txt 2>&1 &\n",
                "wait $!\n",
                "cat /tmp/proc-self.txt\n",
            ),
            check: |s| {
                s.contains("self=true")
                    && s.contains("self_cmdline=true")
                    && s.contains("own_proc=true")
                    && s.contains("own_cmdline=true")
            },
        },
        Def {
            name: "ppid_proc",
            script_template: concat!(
                "{exe} proc-probe > /tmp/ppid-proc.txt 2>&1 &\n",
                "wait $!\n",
                "cat /tmp/ppid-proc.txt\n",
            ),
            check: |s| s.contains("ppid_proc=true"),
        },
        Def {
            name: "ppid_kill0",
            script_template: concat!(
                "{exe} proc-probe > /tmp/ppid-k0.txt 2>&1 &\n",
                "wait $!\n",
                "cat /tmp/ppid-k0.txt\n",
            ),
            check: |s| s.contains("ppid_kill0=true"),
        },
        Def {
            name: "ppid_cmdline",
            script_template: concat!(
                "{exe} proc-probe > /tmp/ppid-cl.txt 2>&1 &\n",
                "wait $!\n",
                "cat /tmp/ppid-cl.txt\n",
            ),
            check: |s| s.contains("ppid_cmdline=true"),
        },
        Def {
            name: "getppid_correct",
            script_template: concat!(
                "echo $$\n",
                "{exe} check-ppid > /tmp/ppid-val.txt 2>&1 &\n",
                "wait $!\n",
                "cat /tmp/ppid-val.txt\n",
            ),
            check: |s| {
                let lines: Vec<&str> = s.lines().collect();
                if lines.len() < 2 {
                    return false;
                }
                let parent_pid = lines[0].trim();
                lines
                    .iter()
                    .any(|l| l.contains(&format!("ppid={parent_pid}")))
            },
        },
        Def {
            name: "parent_monitor",
            script_template: concat!(
                "{exe} proc-probe > /tmp/pmon.txt 2>&1 &\n",
                "wait $!\n",
                "cat /tmp/pmon.txt\n",
            ),
            check: |s| s.contains("ppid_proc=true") && s.contains("ppid_kill0=true"),
        },
    ];
    for &agent in AGENTS {
        for def in defs {
            let agent_s = agent.to_string();
            let template: String = def.script_template.into();
            let check = def.check;
            let name = def.name;
            reg.test("fork", "pid_visibility", format!("KP.{name}.{agent}"))
                .timeout(60)
                .build(move |cx| {
                    let handle = cx.require(agent);
                    Box::new(move |run| {
                        let a = agent_s.clone();
                        let t = template.clone();
                        let self_exe = run.self_exe().to_string();
                        Box::pin(async move {
                            let script = t.replace("{exe}", &self_exe);
                            let resp = pf_exec_full(
                                run,
                                &handle,
                                vec!["bash".into(), "-c".into(), script],
                                Some(15),
                                None,
                                vec![],
                            )
                            .await;
                            let pass = matches!(
                                &resp,
                                Response::ExecResult { stdout, .. }
                                    if check(stdout)
                            );
                            super::TestOutcome::new(&a, pass, format!("{resp:?}"))
                        })
                    })
                });
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// KPX: Cross-agent PID and /proc visibility
// ═══════════════════════════════════════════════════════════════════

#[derive(Clone, Copy)]
struct KpxProcCase {
    name: &'static str,
    observer: AgentName,
    target: AgentName,
}

const KPX_PROC_CASES: &[KpxProcCase] = &[
    KpxProcCase {
        name: "same_agent",
        observer: AgentName::Dpg1,
        target: AgentName::Dpg1,
    },
    KpxProcCase {
        name: "parent_to_child",
        observer: AgentName::Dpg1,
        target: AgentName::Dpg1Dpg1,
    },
    KpxProcCase {
        name: "child_to_parent",
        observer: AgentName::Dpg1Dpg1,
        target: AgentName::Dpg1,
    },
    KpxProcCase {
        name: "root_sibling",
        observer: AgentName::Dpg1,
        target: AgentName::Dpg2,
    },
    KpxProcCase {
        name: "nested_sibling",
        observer: AgentName::Dpg1Dpg1,
        target: AgentName::Dpg1Dpg2,
    },
    KpxProcCase {
        name: "depth1_to_depth2",
        observer: AgentName::Dpg1Dpg2,
        target: AgentName::Dpg1Dpg1Dpg1,
    },
    KpxProcCase {
        name: "depth2_to_depth1",
        observer: AgentName::Dpg1Dpg1Dpg1,
        target: AgentName::Dpg1Dpg2,
    },
    KpxProcCase {
        name: "depth2_sibling",
        observer: AgentName::Dpg1Dpg1Dpg1,
        target: AgentName::Dpg1Dpg1Dpg2,
    },
    KpxProcCase {
        name: "cross_subtree",
        observer: AgentName::Dpg2,
        target: AgentName::Dpg1Dpg1Dpg1,
    },
];

fn kpx_pid(resp: &Response) -> Result<u32, String> {
    match resp {
        Response::Ok { data: Some(pid) } => pid
            .parse::<u32>()
            .map_err(|e| format!("GetPid returned non-numeric pid {pid:?}: {e}")),
        other => Err(format!("GetPid failed: {other:?}")),
    }
}

fn kpx_observe_proc_args(pid: u32) -> PfExecArgs {
    let script = format!(
        "pid={pid}\n\
         if test -d \"/proc/$pid\"; then echo PROC_DIR_OK; else echo PROC_DIR_FAIL; fi\n\
         cat \"/proc/$pid/cmdline\"\n\
         printf '\\n'\n\
         if kill -0 \"$pid\" 2>/dev/null; then echo KILL0_OK; else echo KILL0_FAIL; fi\n"
    );
    pf_exec_timeout_args(vec!["/bin/sh".into(), "-c".into(), script], 10)
}

fn kpx_observe_proc_pass(resp: &Response) -> bool {
    matches!(
        resp,
        Response::ExecResult {
            exit_code: 0,
            stdout,
            ..
        } if stdout.contains("PROC_DIR_OK")
            && stdout.contains("litebox_test_harness")
            && stdout.contains("KILL0_OK")
    )
}

#[allow(clippy::too_many_lines)] // exhaustive pair matrix
pub(crate) fn register_cross_pid_visibility_tests(reg: &mut Registry<'_>) {
    register_platform_fix_handlers();
    for &case in KPX_PROC_CASES {
        let observer = case.observer;
        let target = case.target;
        let test_id = format!("KPX.cross.{}.{}.to.{target}", case.name, observer);
        reg.test("fork", "cross_pid_visibility", test_id)
            .timeout(60)
            .build(move |cx| {
                let observer_handle = cx.require(observer);
                let target_handle = cx.require(target);
                Box::new(move |run| {
                    Box::pin(async move {
                        let pid_resp = pf_get_pid(run, &target_handle).await;
                        let pid = match kpx_pid(&pid_resp) {
                            Ok(pid) => pid,
                            Err(e) => {
                                return super::TestOutcome::new(
                                    observer.name(),
                                    false,
                                    format!("{e}; resp={pid_resp:?}"),
                                );
                            }
                        };
                        let observe_resp = pf_send_response(
                            run,
                            &observer_handle,
                            &PF_EXEC,
                            kpx_observe_proc_args(pid),
                        )
                        .await;
                        let pass = kpx_observe_proc_pass(&observe_resp);
                        super::TestOutcome::new(
                            observer.name(),
                            pass,
                            format!(
                                "observer={observer} target={target} target_pid={pid} pid_resp={pid_resp:?} observe_resp={observe_resp:?}"
                            ),
                        )
                    })
                })
            });
    }
}

// ═══════════════════════════════════════════════════════════════════
// FR: File-Redirect — stdout of background process → file
// ═══════════════════════════════════════════════════════════════════

#[allow(clippy::too_many_lines)] // exhaustive registration / runner
pub(crate) fn register_file_redirect_tests(reg: &mut Registry<'_>) {
    register_platform_fix_handlers();
    struct Def {
        name: &'static str,
        script_template: &'static str,
        check: fn(&str) -> bool,
        /// If true, the template substitutes `{exe}` and the test
        /// gains a `BinaryType` axis. Otherwise the test is a pure
        /// shell-builtin operation with no binary dimension.
        per_binary_type: bool,
    }
    let defs: &[Def] = &[
        Def {
            name: "fg_redirect",
            script_template: concat!("echo FR_FG > {path}\n", "cat {path}\n"),
            check: |s| s.contains("FR_FG"),
            per_binary_type: false,
        },
        Def {
            name: "bg_echo",
            script_template: concat!("echo FR_BGECHO > {path} &\n", "wait\n", "cat {path}\n"),
            check: |s| s.contains("FR_BGECHO"),
            per_binary_type: false,
        },
        Def {
            name: "bg_exe",
            script_template: concat!("{exe} echo-test > {path} &\n", "wait\n", "cat {path}\n"),
            check: |s| s.contains("ECHO_TEST_OK"),
            per_binary_type: true,
        },
        Def {
            name: "bg_cat_pipe",
            script_template: concat!("echo FR_PIPE | cat > {path} &\n", "wait\n", "cat {path}\n",),
            check: |s| s.contains("FR_PIPE"),
            per_binary_type: false,
        },
        Def {
            name: "bg_append",
            script_template: concat!(
                "echo LINE1 > {path}\n",
                "echo LINE2 >> {path} &\n",
                "wait\n",
                "cat {path}\n",
            ),
            check: |s| s.contains("LINE1") && s.contains("LINE2"),
            per_binary_type: false,
        },
    ];
    for &agent in AGENTS {
        for def in defs {
            // For per-binary-type variants, generate a test per leg of
            // BinaryType::ALL. For shell-builtin variants, generate
            // exactly one test (the binary type is irrelevant).
            let bts: &[Option<crate::BinaryType>] = if def.per_binary_type {
                &[
                    Some(crate::BinaryType::PieGlibc),
                    Some(crate::BinaryType::NonPieGlibc),
                    Some(crate::BinaryType::StaticPieGlibc),
                    Some(crate::BinaryType::StaticPieMusl),
                    Some(crate::BinaryType::NonPieStaticMusl),
                ]
            } else {
                &[None]
            };
            for &bt_opt in bts {
                let agent_s = agent.to_string();
                let template: String = def.script_template.into();
                let check = def.check;
                let name = def.name;
                let test_id = match bt_opt {
                    None => format!("FR.{name}.{agent}"),
                    Some(bt) => format!("FR.{name}.{}.{agent}", bt.label()),
                };
                let path_label = match bt_opt {
                    None => name.to_string(),
                    Some(bt) => format!("{name}-{}", bt.label()),
                };
                reg.test("shell", "file_redirect", test_id)
                    .timeout(60)
                    .build(move |cx| {
                        let handle = cx.require(agent);
                        Box::new(move |run| {
                            let a = agent_s.clone();
                            let t = template.clone();
                            let path_label = path_label.clone();
                            let self_exe = run.self_exe().to_string();
                            Box::pin(async move {
                                let path = format!("/shared/fr-{path_label}-{a}.txt");
                                let exe_path = match bt_opt {
                                    None => self_exe.clone(),
                                    Some(bt) => crate::binary_path(bt, &self_exe),
                                };
                                let script = t.replace("{path}", &path).replace("{exe}", &exe_path);
                                let resp = pf_exec_full(
                                    run,
                                    &handle,
                                    vec!["bash".into(), "-c".into(), script],
                                    Some(10),
                                    None,
                                    vec![],
                                )
                                .await;
                                let pass = matches!(
                                    &resp,
                                    Response::ExecResult { stdout, .. }
                                        if check(stdout)
                                );
                                super::TestOutcome::new(&a, pass, format!("{resp:?}"))
                            })
                        })
                    });
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// CSM: CLI Startup Mimic — VS Code CLI link-mode startup shape
// ═══════════════════════════════════════════════════════════════════

pub(crate) fn register_cli_startup_mimic_tests(reg: &mut Registry<'_>) {
    register_platform_fix_handlers();
    const DELIVERIES: &[&str] = &["tokio_pipe", "bash_heredoc_pipe"];

    for &delivery in DELIVERIES {
        for &bt in crate::BinaryType::ALL {
            for &agent in AGENTS {
                let agent_s = agent.to_string();
                let bt_label = bt.label();
                let test_id = format!("CSM.{delivery}.{bt_label}.{agent}");
                reg.test("fork", "cli_startup_mimic", test_id)
                    .timeout(60)
                    .build(move |cx| {
                        let leaf = cx.declare_ephemeral(
                            agent,
                            format!("CliStartupMimic_{delivery}_{bt_label}_{agent}"),
                            SpawnKind::Fork {
                                binary: fork_binary_label(bt),
                                inherit_listen_ports: vec![],
                            },
                        );
                        Box::new(move |run| {
                            let a = agent_s.clone();
                            Box::pin(async move {
                                let result = run
                                    .run_leaf(&leaf, &CLI_STARTUP_MIMIC, CliStartupMimicArgs {})
                                    .await;
                                let pass = matches!(&result, Ok(out) if out.detail.contains("CLI_STARTUP_MIMIC_OK"));
                                super::TestOutcome::new(&a, pass, format!("{result:?}"))
                            })
                        })
                    });
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// BR: Background Redirect Poll — file visibility while backgrounded
// ═══════════════════════════════════════════════════════════════════

#[allow(clippy::too_many_lines)] // exhaustive registration / runner
pub(crate) fn register_bg_redirect_poll_tests(reg: &mut Registry<'_>) {
    register_platform_fix_handlers();
    #[derive(Clone, Copy)]
    struct Def {
        name: &'static str,
        marker: &'static str,
        script_template: &'static str,
        per_binary_type: bool,
    }

    let defs = [
        Def {
            name: "subshell_stdout",
            marker: "BR_SUBSHELL_STDOUT",
            script_template: "(echo BR_SUBSHELL_STDOUT; sleep 1) > {path} &\n",
            per_binary_type: false,
        },
        Def {
            name: "exe_stdout",
            marker: "ECHO_TEST_OK",
            script_template: "{exe} echo-test > {path} &\n",
            per_binary_type: true,
        },
        Def {
            name: "exe_stderr",
            marker: "STDERR_ONLY_OK",
            script_template: "{exe} stderr-only-test > {path} 2>&1 &\n",
            per_binary_type: true,
        },
    ];

    for &agent in AGENTS {
        for def in defs {
            let bts: &[Option<crate::BinaryType>] = if def.per_binary_type {
                &[
                    Some(crate::BinaryType::PieGlibc),
                    Some(crate::BinaryType::NonPieGlibc),
                    Some(crate::BinaryType::StaticPieGlibc),
                    Some(crate::BinaryType::StaticPieMusl),
                    Some(crate::BinaryType::NonPieStaticMusl),
                ]
            } else {
                &[None]
            };
            for &bt_opt in bts {
                let agent_s = agent.to_string();
                let test_id = match bt_opt {
                    None => format!("BR.{}.{agent}", def.name),
                    Some(bt) => format!("BR.{}.{}.{agent}", def.name, bt.label()),
                };
                let path_label = match bt_opt {
                    None => def.name.to_string(),
                    Some(bt) => format!("{}-{}", def.name, bt.label()),
                };
                reg.test("shell", "bg_redirect_poll", test_id)
                    .timeout(60)
                    .build(move |cx| {
                        let handle = cx.require(agent);
                        Box::new(move |run| {
                            let a = agent_s.clone();
                            let path_label = path_label.clone();
                            let self_exe = run.self_exe().to_string();
                            Box::pin(async move {
                                let path = format!("/shared/br-{path_label}-{a}.txt");
                                let exe_path = match bt_opt {
                                    None => self_exe.clone(),
                                    Some(bt) => crate::binary_path(bt, &self_exe),
                                };
                                let script = format!(
                                    "{}PID=$!\nfor _ in 1 2 3 4 5 6 7 8 9 10; do\n  if grep -q '{}' '{}'; then\n    kill $PID 2>/dev/null; wait $PID 2>/dev/null\n    cat '{}'\n    exit 0\n  fi\n  sleep 0.1\ndone\nkill $PID 2>/dev/null; wait $PID 2>/dev/null\ncat '{}' 2>/dev/null\nexit 1\n",
                                    def.script_template
                                        .replace("{path}", &path)
                                        .replace("{exe}", &exe_path),
                                    def.marker,
                                    path,
                                    path,
                                    path,
                                );
                                let resp = pf_exec_full(run, &handle, vec!["bash".into(), "-c".into(), script], Some(10), None, vec![]).await;
                                let pass = matches!(
                                    &resp,
                                    Response::ExecResult { exit_code: 0, stdout, .. }
                                        if stdout.contains(def.marker)
                                );
                                super::TestOutcome::new(&a, pass, format!("{resp:?}"))
                            })
                        })
                    });
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// BRS: Background Redirect Stdin Poll — stdin pipe + stdout redirect
// ═══════════════════════════════════════════════════════════════════

#[allow(clippy::too_many_lines)] // exhaustive registration / runner
pub(crate) fn register_bg_redirect_stdin_poll_tests(reg: &mut Registry<'_>) {
    register_platform_fix_handlers();
    #[derive(Clone, Copy)]
    struct Def {
        name: &'static str,
        consumer_template: &'static str,
        per_binary_type: bool,
    }

    const SHELLS: &[(&str, &str)] = &[("bash", "bash"), ("sh", "sh")];
    const DELIVERIES: &[&str] = &["tokio_pipe", "bash_heredoc_pipe"];
    let defs = [
        Def {
            name: "subshell_stdin",
            consumer_template: "cat",
            per_binary_type: false,
        },
        Def {
            name: "exe_stdin",
            consumer_template: "{exe} stdin-echo-test",
            per_binary_type: true,
        },
    ];

    for &agent in AGENTS {
        for &(shell_name, shell_bin) in SHELLS {
            for &delivery in DELIVERIES {
                for def in defs {
                    let bts: &[Option<crate::BinaryType>] = if def.per_binary_type {
                        &[
                            Some(crate::BinaryType::PieGlibc),
                            Some(crate::BinaryType::NonPieGlibc),
                            Some(crate::BinaryType::StaticPieGlibc),
                            Some(crate::BinaryType::StaticPieMusl),
                            Some(crate::BinaryType::NonPieStaticMusl),
                        ]
                    } else {
                        &[None]
                    };
                    for &bt_opt in bts {
                        let agent_s = agent.to_string();
                        let test_id = match bt_opt {
                            None => format!("BRS.{}.{shell_name}.{delivery}.{agent}", def.name),
                            Some(bt) => format!(
                                "BRS.{}.{shell_name}.{delivery}.{}.{agent}",
                                def.name,
                                bt.label()
                            ),
                        };
                        let path_label = match bt_opt {
                            None => def.name.to_string(),
                            Some(bt) => format!("{}-{}", def.name, bt.label()),
                        };
                        reg.test("shell", "bg_redirect_stdin_poll", test_id)
                            .timeout(60)
                            .build(move |cx| {
                                let handle = cx.require(agent);
                                Box::new(move |run| {
                                    let a = agent_s.clone();
                                    let path_label = path_label.clone();
                                    let self_exe = run.self_exe().to_string();
                                    Box::pin(async move {
                                        let path = format!(
                                            "/shared/brs-{path_label}-{shell_name}-{delivery}-{a}.txt"
                                        );
                                        let marker = format!(
                                            "BRS_PAYLOAD_{}_{}_{}",
                                            def.name, shell_name, delivery
                                        );
                                        let exe_path = match bt_opt {
                                            None => self_exe.clone(),
                                            Some(bt) => crate::binary_path(bt, &self_exe),
                                        };
                                        let consumer = def
                                            .consumer_template
                                            .replace("{exe}", &exe_path);
                                        let (producer_script, stdin) = match delivery {
                                            "tokio_pipe" => (
                                                format!("cat | {consumer} > {path} &\n"),
                                                Some(format!("{marker}\n")),
                                            ),
                                            "bash_heredoc_pipe" => (
                                                format!(
                                                    "cat <<'BRS_EOF' | {consumer} > {path} &\n{marker}\nBRS_EOF\n"
                                                ),
                                                None,
                                            ),
                                            _ => unreachable!(),
                                        };
                                        let script = format!(
                                            "{producer_script}PID=$!\nfor _ in 1 2 3 4 5 6 7 8 9 10; do\n  if grep -q '{marker}' '{path}'; then\n    wait $PID 2>/dev/null\n    cat '{path}'\n    exit 0\n  fi\n  sleep 0.1\ndone\nkill $PID 2>/dev/null; wait $PID 2>/dev/null\ncat '{path}' 2>/dev/null\nexit 1\n"
                                        );
                                        let resp = pf_exec_full(
                                            run,
                                            &handle,
                                            vec![shell_bin.into(), "-c".into(), script],
                                            Some(10),
                                            stdin,
                                            vec![],
                                        )
                                        .await;
                                        let pass = matches!(
                                            &resp,
                                            Response::ExecResult { exit_code: 0, stdout, .. }
                                                if stdout.contains(&marker)
                                        );
                                        super::TestOutcome::new(&a, pass, format!("{resp:?}"))
                                    })
                                })
                            });
                    }
                }
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// PN: Pipe Non-blocking
// ═══════════════════════════════════════════════════════════════════

pub(crate) fn register_pipe_nonblock_tests(reg: &mut Registry<'_>) {
    register_platform_fix_handlers();
    // Part 1: basic pipe non-blocking (single process)
    for &agent in AGENTS {
        for &(suffix, marker) in &[
            ("setfl", "PIPE_NB_SETFL=OK"),
            ("empty_eagain", "PIPE_NB_EMPTY=EAGAIN"),
            ("data", "PIPE_NB_DATA=OK"),
            ("eof", "PIPE_NB_EOF=OK"),
        ] {
            let agent_s = agent.to_string();
            let marker_s: String = marker.into();
            reg.test("matrix", "pipe_nonblock", format!("PN.{agent}.{suffix}"))
                .timeout(60)
                .build(move |cx| {
                    let leaf = cx.declare_ephemeral(
                        agent,
                        format!("PipeNonblock_{agent}_{suffix}"),
                        SpawnKind::Fork {
                            binary: "self",
                            inherit_listen_ports: vec![],
                        },
                    );
                    Box::new(move |run| {
                        let a = agent_s.clone();
                        let m = marker_s.clone();
                        Box::pin(async move {
                            let result = run
                                .run_leaf(&leaf, &PIPE_NONBLOCK, PipeNonblockArgs {})
                                .await;
                            let pass = matches!(&result, Ok(out) if out.detail.contains(&*m));
                            super::TestOutcome::new(&a, pass, format!("{result:?}"))
                        })
                    })
                });
        }
    }

    // Part 2: cross-process pipe non-blocking (dropbear pattern)
    for &agent in DEPTH_AGENTS {
        for &(suffix, marker) in &[
            ("eagain", "PCHILD_INITIAL=EAGAIN"),
            ("data", "PCHILD_DATA=OK"),
            ("eof", "PCHILD_EOF=OK"),
        ] {
            let agent_s = agent.to_string();
            let marker_s: String = marker.into();
            reg.test(
                "matrix",
                "pipe_nonblock",
                format!("PN.child.{agent}.{suffix}"),
            )
            .timeout(60)
            .build(move |cx| {
                let leaf = cx.declare_ephemeral(
                    agent,
                    format!("PipeChildNonblock_{agent}_{suffix}"),
                    SpawnKind::Fork {
                        binary: "self",
                        inherit_listen_ports: vec![],
                    },
                );
                Box::new(move |run| {
                    let a = agent_s.clone();
                    let m = marker_s.clone();
                    Box::pin(async move {
                        let result = run
                            .run_leaf(&leaf, &PIPE_CHILD_NONBLOCK, PipeChildNonblockArgs {})
                            .await;
                        let pass = matches!(&result, Ok(out) if out.detail.contains(&*m));
                        super::TestOutcome::new(&a, pass, format!("{result:?}"))
                    })
                })
            });
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// EP: Epoll + Socket wakeup
// ═══════════════════════════════════════════════════════════════════

#[allow(clippy::too_many_lines)]
pub(crate) fn register_epoll_socket_tests(reg: &mut Registry<'_>) {
    register_platform_fix_handlers();
    for &variant in &["direct", "tokio"] {
        // Long-lived agents the epoll/socket test runs in. Each
        // entry is a forking parent of a different binary type; the
        // syscall-rewrite / vDSO / epoll-host code path differs per
        // parent binary, so we want a slot per leg.
        for &agent in &[
            AgentName::Dpg1,       // PIE-glibc
            AgentName::Dpg1Dpg1,   // PIE-glibc depth-2
            AgentName::Dpg2,       // PIE-glibc sibling
            AgentName::Dpg1Dng,    // non-PIE-glibc (node form)
            AgentName::Dpg1DngDpg, // PIE child of non-PIE — round-trip
            AgentName::Dpg1DngDng, // bash → bash (VS Code hot path)
            AgentName::Dpg1DngSpm, // bash → cli (VS Code hot path)
            AgentName::Dpg1Spg,    // static-PIE-glibc
            AgentName::Dpg1Spm,    // static-PIE-musl (cli form)
            AgentName::Dpg1SpmDng, // cli → node (VS Code signature)
            AgentName::Dpg1Snm,    // non-PIE-static-musl
        ] {
            let port: u16 = match (variant, agent) {
                ("direct", AgentName::Dpg1) => 19990,
                ("direct", AgentName::Dpg1Dpg1) => 19991,
                ("direct", AgentName::Dpg2) => 19992,
                ("direct", AgentName::Dpg1Dng) => 19993,
                ("direct", AgentName::Dpg1DngDpg) => 19994,
                ("direct", AgentName::Dpg1Spg) => 19980,
                ("direct", AgentName::Dpg1Spm) => 19981,
                ("direct", AgentName::Dpg1Snm) => 19982,
                ("direct", AgentName::Dpg1DngDng) => 19970,
                ("direct", AgentName::Dpg1DngSpm) => 19971,
                ("direct", AgentName::Dpg1SpmDng) => 19972,
                ("tokio", AgentName::Dpg1) => 19995,
                ("tokio", AgentName::Dpg1Dpg1) => 19996,
                ("tokio", AgentName::Dpg2) => 19997,
                ("tokio", AgentName::Dpg1Dng) => 19998,
                ("tokio", AgentName::Dpg1DngDpg) => 19999,
                ("tokio", AgentName::Dpg1Spg) => 19985,
                ("tokio", AgentName::Dpg1Spm) => 19986,
                ("tokio", AgentName::Dpg1Snm) => 19987,
                ("tokio", AgentName::Dpg1DngDng) => 19975,
                ("tokio", AgentName::Dpg1DngSpm) => 19976,
                ("tokio", AgentName::Dpg1SpmDng) => 19977,
                _ => 19960,
            };

            // EP.{variant}.accept.{agent}
            {
                let agent_s = agent.to_string();
                let variant_s: String = variant.into();
                reg.test("matrix", "epoll_socket", format!("EP.{variant}.accept.{agent}"))
                    .timeout(60)
                    .build(move |cx| {
                        let leaf = cx.declare_ephemeral(
                            agent,
                            format!("EpollSocketAccept_{variant}_{agent}"),
                            SpawnKind::Fork {
                                binary: "self",
                                inherit_listen_ports: vec![],
                            },
                        );
                        Box::new(move |run| {
                            let a = agent_s.clone();
                            let v = variant_s.clone();
                            Box::pin(async move {
                                let result = run
                                    .run_leaf(
                                        &leaf,
                                        &EPOLL_SOCKET,
                                        EpollSocketArgs { port, variant: v },
                                    )
                                    .await;
                                let pass = matches!(&result, Ok(out) if out.detail.contains("EPOLL_ACCEPT=") && !out.detail.contains("TIMEOUT"));
                                super::TestOutcome::new(&a, pass, format!("{result:?}"))
                            })
                        })
                    });
            }

            // EP.{variant}.read.{agent}
            {
                let agent_s = agent.to_string();
                let variant_s: String = variant.into();
                reg.test(
                    "matrix",
                    "epoll_socket",
                    format!("EP.{variant}.read.{agent}"),
                )
                .timeout(60)
                .build(move |cx| {
                    let leaf = cx.declare_ephemeral(
                        agent,
                        format!("EpollSocketRead_{variant}_{agent}"),
                        SpawnKind::Fork {
                            binary: "self",
                            inherit_listen_ports: vec![],
                        },
                    );
                    Box::new(move |run| {
                        let a = agent_s.clone();
                        let v = variant_s.clone();
                        Box::pin(async move {
                            let result = run
                                .run_leaf(
                                    &leaf,
                                    &EPOLL_SOCKET,
                                    EpollSocketArgs { port, variant: v },
                                )
                                .await;
                            let pass =
                                matches!(&result, Ok(out) if out.detail.contains("EPOLL_READ=OK"));
                            super::TestOutcome::new(&a, pass, format!("{result:?}"))
                        })
                    })
                });
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// THC: TCP half-close EOF
// ═══════════════════════════════════════════════════════════════════

pub(crate) fn register_tcp_halfclose_tests(reg: &mut Registry<'_>) {
    #[derive(Clone, Copy)]
    struct Case {
        id: &'static str,
        server: AgentName,
        client: AgentName,
        payload: &'static str,
    }

    let cases = [
        Case {
            id: "THC.halfclose.eof.same_agent",
            server: AgentName::Dpg1,
            client: AgentName::Dpg1,
            payload: "THC_SAME_AGENT_PAYLOAD",
        },
        Case {
            id: "THC.halfclose.eof.cross_agent",
            server: AgentName::Dpg1,
            client: AgentName::Dpg2,
            payload: "THC_CROSS_AGENT_PAYLOAD",
        },
        Case {
            id: "THC.halfclose.eof.sibling",
            server: AgentName::Dpg1Dpg1,
            client: AgentName::Dpg1Dpg2,
            payload: "THC_SIBLING_PAYLOAD",
        },
        Case {
            id: "THC.halfclose.eof.depth2",
            server: AgentName::Dpg1Dpg1Dpg1,
            client: AgentName::Dpg1Dpg1Dpg2,
            payload: "THC_DEPTH2_PAYLOAD",
        },
    ];

    for case in cases {
        let server_label = case.server.to_string();
        let client_label = case.client.to_string();
        reg.test("matrix", "tcp_halfclose", case.id)
            .timeout(60)
            .build(move |cx| {
                let server = cx.require(case.server);
                let client = cx.require(case.client);
                Box::new(move |run| {
                    let server_label = server_label.clone();
                    let client_label = client_label.clone();
                    let payload = case.payload.to_string();
                    Box::pin(async move {
                        crate::coordinator::tcp_state::run_write_shutdown_read_eof_case(
                            run,
                            &server,
                            &client,
                            &server_label,
                            &client_label,
                            &payload,
                        )
                        .await
                    })
                })
            });
    }
}

// ═══════════════════════════════════════════════════════════════════
// FKLC: fork-listen-close — VS Code CLI pattern
// ═══════════════════════════════════════════════════════════════════

async fn fklc_connect_from_agent(
    run: &mut RunContext<'_>,
    connector: &AgentHandle,
    port: u16,
    payload: &str,
) -> Result<Response, String> {
    let resp = pf_net_connect(
        run,
        connector,
        format!("127.0.0.1:{port}"),
        payload.to_string(),
    )
    .await;
    match &resp {
        Response::Connected { echo } if echo == payload => Ok(resp),
        _ => Err(format!("connect via agent failed: {resp:?}")),
    }
}

async fn fklc_child_accept_ready(
    run: &mut RunContext<'_>,
    child: &EphemeralHandle,
    port: u16,
) -> Result<Response, String> {
    let args = serde_json::to_value(AcceptInheritedArgs {
        port,
        timeout_secs: 5,
    })
    .map_err(|e| format!("accept args serialize: {e}"))?;
    let resp = run
        .forward(
            child,
            InfraCommand::Run {
                handler: ACCEPT_INHERITED.name().to_string(),
                args,
            },
        )
        .await;
    match &resp {
        Response::Result { ok: true, .. } => Ok(resp),
        _ => Err(format!("child accept start failed: {resp:?}")),
    }
}

#[allow(clippy::too_many_lines)]
pub(crate) fn register_fork_listen_close_tests(reg: &mut Registry<'_>) {
    register_handler!(ACCEPT_INHERITED, handle_accept_inherited);
    register_handler!(CLOSE_INHERITED, handle_close_inherited);
    // FKLC.listen_unlisten: A listens then immediately unlistens,
    // B connects — should get RST.
    reg.test(
        "xworker",
        "fork_listen_close",
        "FKLC.listen_unlisten".to_string(),
    )
    .timeout(60)
    .build(move |cx| {
        let handle_a = cx.require(AgentName::Dpg1);
        let handle_b = cx.require(AgentName::Dpg2);
        Box::new(move |run| {
            Box::pin(async move {
                let port = 19920u16;
                let listen_resp = pf_net_listen(run, &handle_a, port).await;
                if let Err(e) = super::expect_listening_port(&listen_resp, port) {
                    return super::TestOutcome::new(
                        "B",
                        false,
                        format!("listen failed: {e}; resp={listen_resp:?}"),
                    );
                }
                let _ = pf_net_unlisten(run, &handle_a, port).await;
                let conn_resp = pf_net_connect(
                    run,
                    &handle_b,
                    format!("127.0.0.1:{port}"),
                    "listen_unlisten".into(),
                )
                .await;
                let got_rst = matches!(
                    &conn_resp,
                    Response::ConnectFailed { error }
                        if !error.is_empty()
                            && (error.contains("refused")
                                || error.contains("reset")
                                || error.contains("timeout"))
                );
                super::TestOutcome::new("B", got_rst, format!("expected RST: {conn_resp:?}"))
            })
        })
    });
    // FKLC.inherit.cross_connect.{pair}: protocol-only fd inheritance
    // across fork+exec, exercising the full cross-worker fd transport
    // surface across binary-type transitions.
    //
    // Three actors:
    //   - parent: AgentName that listens on the port, then forks an
    //     ephemeral child via SpawnKind::Fork{binary:"self",...}.
    //     Binary type of child == binary type of parent.
    //   - inheriting child: forked from parent, inherits the listen fd,
    //     accepts incoming connections.
    //   - connector: separate top-level agent that connects to the
    //     listened port from a sibling worker tree.
    //
    // Matrix axes:
    //   - parent binary type (5 values) → exercises Path A
    //     (host-pipe-bridge fork-restore migration of the listen fd
    //     to the child worker host process). When parent and child
    //     are different binary types, the child runs in a separate
    //     worker process via delayed-fork migration.
    //   - connector binary type (chosen for cross-worker coverage)
    //     → exercises Path B (broker TCP via smoltcp for the connect
    //     side) when connector and listener are in different trees.
    //
    // Pre-architectural-fix (wave-5 baseline): listen-fd inheritance
    // is unimplemented at the product level; child accept(inherited_fd)
    // returns ENOTSOCK. Expected to fail on litebox for ALL pairs;
    // expected to pass on native for ALL pairs.
    //
    // Post-fix: all pairs pass on litebox.
    {
        struct FklcInheritPair {
            name: &'static str,
            parent: AgentName,
            connector: AgentName,
            base_port: u16,
        }
        // 5 parent binary types × Dpg2 connector. Each pair gets a
        // unique base port to avoid bind collisions when tests run in
        // parallel within the same docker container.
        const FKLC_INHERIT_PAIRS: &[FklcInheritPair] = &[
            // PIE-glibc → PIE-glibc, sibling-tree connector.
            // Baseline: parent and child same binary type, no
            // binary-type-transition fork-restore migration.
            FklcInheritPair {
                name: "dpg1",
                parent: AgentName::Dpg1,
                connector: AgentName::Dpg2,
                base_port: 19930,
            },
            // Non-PIE-glibc (within-tree depth-2 from Dpg1).
            // Parent is non-PIE-glibc; child fork+exec self also non-PIE-glibc.
            // Tests Path A across non-PIE-glibc.
            FklcInheritPair {
                name: "dpg1_dng",
                parent: AgentName::Dpg1Dng,
                connector: AgentName::Dpg2,
                base_port: 19931,
            },
            // Static-PIE-glibc parent.
            FklcInheritPair {
                name: "dpg1_spg",
                parent: AgentName::Dpg1Spg,
                connector: AgentName::Dpg2,
                base_port: 19932,
            },
            // Static-PIE-musl parent — VS Code CLI pattern's binary type.
            FklcInheritPair {
                name: "dpg1_spm",
                parent: AgentName::Dpg1Spm,
                connector: AgentName::Dpg2,
                base_port: 19933,
            },
            // Non-PIE-static-musl parent.
            FklcInheritPair {
                name: "dpg1_snm",
                parent: AgentName::Dpg1Snm,
                connector: AgentName::Dpg2,
                base_port: 19934,
            },
        ];

        for pair in FKLC_INHERIT_PAIRS {
            let id = format!("FKLC.inherit.cross_connect.{}", pair.name);
            let parent = pair.parent;
            let connector = pair.connector;
            let port = pair.base_port;
            let ephemeral_label = match pair.name {
                "dpg1" => "FKLCInheritCrossDpg1",
                "dpg1_dng" => "FKLCInheritCrossDpg1Dng",
                "dpg1_spg" => "FKLCInheritCrossDpg1Spg",
                "dpg1_spm" => "FKLCInheritCrossDpg1Spm",
                "dpg1_snm" => "FKLCInheritCrossDpg1Snm",
                _ => unreachable!(),
            };
            reg.test("xworker", "fork_listen_close", id)
                .timeout(60)
                .build(move |cx| {
                    let parent_handle = cx.require(parent);
                    let connector_handle = cx.require(connector);
                    let child = cx.declare_ephemeral(
                        parent,
                        ephemeral_label,
                        SpawnKind::Fork {
                            binary: "self",
                            inherit_listen_ports: vec![port],
                        },
                    );
                    Box::new(move |run| {
                        Box::pin(async move {
                            let listen_resp = pf_net_listen(run, &parent_handle, port).await;
                            if !matches!(&listen_resp, Response::Listening { port: p } if *p == port) {
                                return super::TestOutcome::new(
                                    "B",
                                    false,
                                    format!("listen failed: {listen_resp:?}"),
                                );
                            }
                            let fork_resp = run.spawn_ephemeral(&child).await;
                            if !matches!(&fork_resp, Response::Ok { .. }) {
                                return super::TestOutcome::new(
                                    "B",
                                    false,
                                    format!("fork failed: {fork_resp:?}"),
                                );
                            }
                            let _ = pf_net_unlisten(run, &parent_handle, port).await;
                            if let Err(e) = fklc_child_accept_ready(run, &child, port).await {
                                let _ = run.forward(&child, InfraCommand::Exit).await;
                                return super::TestOutcome::new("B", false, e);
                            }
                            match fklc_connect_from_agent(
                                run,
                                &connector_handle,
                                port,
                                "fork_listen_close",
                            )
                            .await
                            {
                                Ok(conn_resp) => {
                                    let _ = run.forward(&child, InfraCommand::Exit).await;
                                    super::TestOutcome::new("B", true, format!("{conn_resp:?}"))
                                }
                                Err(e) => {
                                    let _ = run.forward(&child, InfraCommand::Exit).await;
                                    super::TestOutcome::new("B", false, e)
                                }
                            }
                        })
                    })
                });
        }
    }

    // FKLC.inherit.multi_port: one fork imports two listen sockets at once.
    reg.test(
        "xworker",
        "fork_listen_close",
        "FKLC.inherit.multi_port".to_string(),
    )
    .timeout(60)
    .build(move |cx| {
        let parent = cx.require(AgentName::Dpg1);
        let connector = cx.require(AgentName::Dpg2);
        let child = cx.declare_ephemeral(
            AgentName::Dpg1,
            "FKLCInheritMulti",
            SpawnKind::Fork {
                binary: "self",
                inherit_listen_ports: vec![19922, 19923],
            },
        );
        Box::new(move |run| {
            Box::pin(async move {
                for port in [19922u16, 19923] {
                    let listen_resp = pf_net_listen(run, &parent, port).await;
                    if !matches!(&listen_resp, Response::Listening { port: p } if *p == port) {
                        return super::TestOutcome::new(
                            "B",
                            false,
                            format!("listen {port} failed: {listen_resp:?}"),
                        );
                    }
                }
                let fork_resp = run.spawn_ephemeral(&child).await;
                if !matches!(&fork_resp, Response::Ok { .. }) {
                    return super::TestOutcome::new(
                        "B",
                        false,
                        format!("fork failed: {fork_resp:?}"),
                    );
                }
                for port in [19922u16, 19923] {
                    let _ = pf_net_unlisten(run, &parent, port).await;
                }
                let ready_first = fklc_child_accept_ready(run, &child, 19922).await;
                let ready_second = fklc_child_accept_ready(run, &child, 19923).await;
                let first = fklc_connect_from_agent(run, &connector, 19922, "multi_one").await;
                let second = fklc_connect_from_agent(run, &connector, 19923, "multi_two").await;
                let _ = run.forward(&child, InfraCommand::Exit).await;
                match (ready_first, ready_second, first, second) {
                    (Ok(a), Ok(b), Ok(c), Ok(d)) => {
                        super::TestOutcome::new("B", true, format!("{a:?}; {b:?}; {c:?}; {d:?}"))
                    }
                    results => super::TestOutcome::new("B", false, format!("{results:?}")),
                }
            })
        })
    });

    // FKLC.inherit.close_parent: the child keeps accepting after the parent closes.
    reg.test(
        "xworker",
        "fork_listen_close",
        "FKLC.inherit.close_parent".to_string(),
    )
    .timeout(60)
    .build(move |cx| {
        let parent = cx.require(AgentName::Dpg1);
        let connector = cx.require(AgentName::Dpg2);
        let child = cx.declare_ephemeral(
            AgentName::Dpg1,
            "FKLCInheritCloseParent",
            SpawnKind::Fork {
                binary: "self",
                inherit_listen_ports: vec![19924],
            },
        );
        Box::new(move |run| {
            Box::pin(async move {
                let port = 19924u16;
                let listen_resp = pf_net_listen(run, &parent, port).await;
                if !matches!(&listen_resp, Response::Listening { port: p } if *p == port) {
                    return super::TestOutcome::new(
                        "B",
                        false,
                        format!("listen failed: {listen_resp:?}"),
                    );
                }
                let fork_resp = run.spawn_ephemeral(&child).await;
                let close_resp = pf_net_unlisten(run, &parent, port).await;
                if !matches!(
                    (&fork_resp, &close_resp),
                    (Response::Ok { .. }, Response::Ok { .. })
                ) {
                    return super::TestOutcome::new(
                        "B",
                        false,
                        format!("fork/close failed: {fork_resp:?}; {close_resp:?}"),
                    );
                }
                let ready = fklc_child_accept_ready(run, &child, port).await;
                let result = if let Err(e) = ready {
                    Err(e)
                } else {
                    fklc_connect_from_agent(run, &connector, port, "close_parent").await
                };
                let _ = run.forward(&child, InfraCommand::Exit).await;
                match result {
                    Ok(resp) => super::TestOutcome::new("B", true, format!("{resp:?}")),
                    Err(e) => super::TestOutcome::new("B", false, e),
                }
            })
        })
    });

    // FKLC.inherit.depth2: an inheriting child can fork the listener onward.
    reg.test(
        "xworker",
        "fork_listen_close",
        "FKLC.inherit.depth2".to_string(),
    )
    .timeout(60)
    .build(move |cx| {
        let parent = cx.require(AgentName::Dpg1);
        let connector = cx.require(AgentName::Dpg2);
        let child = cx.declare_ephemeral(
            AgentName::Dpg1,
            "FKLCInheritDepth1",
            SpawnKind::Fork {
                binary: "self",
                inherit_listen_ports: vec![19925],
            },
        );
        Box::new(move |run| {
            Box::pin(async move {
                let port = 19925u16;
                let listen_resp = pf_net_listen(run, &parent, port).await;
                if !matches!(&listen_resp, Response::Listening { port: p } if *p == port) {
                    return super::TestOutcome::new(
                        "B",
                        false,
                        format!("listen failed: {listen_resp:?}"),
                    );
                }
                let fork1_resp = run.spawn_ephemeral(&child).await;
                let _ = pf_net_unlisten(run, &parent, port).await;
                if !matches!(&fork1_resp, Response::Ok { .. }) {
                    return super::TestOutcome::new(
                        "B",
                        false,
                        format!("fork depth1 failed: {fork1_resp:?}"),
                    );
                }
                let fork2_resp = run
                    .forward(
                        &child,
                        InfraCommand::Fork {
                            name: "FKLCInheritDepth2".into(),
                            binary: "self".into(),
                            inherit_listen_ports: vec![port],
                        },
                    )
                    .await;
                let close1_resp = run
                    .forward(
                        &child,
                        InfraCommand::Run {
                            handler: CLOSE_INHERITED.name().to_string(),
                            args: serde_json::to_value(ClosePortArgs { port })
                                .expect("close args serialize"),
                        },
                    )
                    .await;
                if !matches!(
                    (&fork2_resp, &close1_resp),
                    (Response::Ok { .. }, Response::Result { ok: true, .. })
                ) {
                    let _ = run.forward(&child, InfraCommand::Exit).await;
                    return super::TestOutcome::new(
                        "B",
                        false,
                        format!("fork depth2/close depth1 failed: {fork2_resp:?}; {close1_resp:?}"),
                    );
                }
                let ready_args = serde_json::to_value(AcceptInheritedArgs {
                    port,
                    timeout_secs: 5,
                })
                .expect("accept args serialize");
                let ready = run
                    .forward(
                        &child,
                        InfraCommand::Forward {
                            target: "FKLCInheritDepth2".into(),
                            inner: Box::new(InfraCommand::Run {
                                handler: ACCEPT_INHERITED.name().to_string(),
                                args: ready_args,
                            }),
                        },
                    )
                    .await;
                let conn = fklc_connect_from_agent(run, &connector, port, "depth2").await;
                let _ = run
                    .forward(
                        &child,
                        InfraCommand::Forward {
                            target: "FKLCInheritDepth2".into(),
                            inner: Box::new(InfraCommand::Exit),
                        },
                    )
                    .await;
                let _ = run.forward(&child, InfraCommand::Exit).await;
                match (&ready, conn) {
                    (Response::Result { ok: true, .. }, Ok(conn_resp)) => {
                        super::TestOutcome::new("B", true, format!("{ready:?}; {conn_resp:?}"))
                    }
                    (_, conn_result) => super::TestOutcome::new(
                        "B",
                        false,
                        format!("ready={ready:?}; connect={conn_result:?}"),
                    ),
                }
            })
        })
    });

    // FKLC.inherit.sibling_connect: a sibling child, not the parent, connects.
    reg.test(
        "xworker",
        "fork_listen_close",
        "FKLC.inherit.sibling_connect".to_string(),
    )
    .timeout(60)
    .build(move |cx| {
        let parent = cx.require(AgentName::Dpg1);
        let connector = cx.require(AgentName::Dpg2);
        let server = cx.declare_ephemeral(
            AgentName::Dpg1,
            "FKLCInheritSiblingServer",
            SpawnKind::Fork {
                binary: "self",
                inherit_listen_ports: vec![19926],
            },
        );
        Box::new(move |run| {
            Box::pin(async move {
                let port = 19926u16;
                let listen_resp = pf_net_listen(run, &parent, port).await;
                if !matches!(&listen_resp, Response::Listening { port: p } if *p == port) {
                    return super::TestOutcome::new(
                        "A",
                        false,
                        format!("listen failed: {listen_resp:?}"),
                    );
                }
                let server_resp = run.spawn_ephemeral(&server).await;
                let _ = pf_net_unlisten(run, &parent, port).await;
                if !matches!(&server_resp, Response::Ok { .. }) {
                    return super::TestOutcome::new(
                        "B",
                        false,
                        format!("spawn failed: {server_resp:?}"),
                    );
                }
                let ready = fklc_child_accept_ready(run, &server, port).await;
                let result = if let Err(e) = ready {
                    Err(e)
                } else {
                    fklc_connect_from_agent(run, &connector, port, "sibling_connect").await
                };
                let _ = run.forward(&server, InfraCommand::Exit).await;
                match result {
                    Ok(resp) => super::TestOutcome::new("B", true, format!("{resp:?}")),
                    Err(e) => super::TestOutcome::new("B", false, e),
                }
            })
        })
    });
}

// ═══════════════════════════════════════════════════════════════════
// PROC: /proc filesystem tests
// ═══════════════════════════════════════════════════════════════════

pub(crate) fn register_proc_filesystem_tests(reg: &mut Registry<'_>) {
    register_platform_fix_handlers();
    for &agent in AGENTS {
        let agent_s = agent.to_string();

        // PROC.self_stat: /proc/self/stat is readable.
        {
            let a = agent_s.clone();
            reg.test(
                "matrix",
                "proc_filesystem",
                format!("PROC.self_stat.{agent}"),
            )
            .timeout(60)
            .build(move |cx| {
                let handle = cx.require(agent);
                Box::new(move |run| {
                    let a = a.clone();
                    Box::pin(async move {
                        let resp = pf_fs_read(run, &handle, "/proc/self/stat".into()).await;
                        let pass =
                            matches!(&resp, Response::Ok { data: Some(d) } if d.contains(") "));
                        super::TestOutcome::new(&a, pass, format!("{resp:?}"))
                    })
                })
            });
        }

        // PROC.stat_seekable: /proc/self/stat is seekable (lseek).
        {
            let a = agent_s.clone();
            reg.test(
                "matrix",
                "proc_filesystem",
                format!("PROC.stat_seekable.{agent}"),
            )
            .timeout(60)
            .build(move |cx| {
                let handle = cx.require(agent);
                Box::new(move |run| {
                    let a = a.clone();
                    Box::pin(async move {
                        let resp = pf_exec(
                            run,
                            &handle,
                            vec![
                                "sh".into(),
                                "-c".into(),
                                "dd if=/proc/self/stat bs=1 skip=0 count=10 2>/dev/null | wc -c"
                                    .into(),
                            ],
                        )
                        .await;
                        let pass = matches!(
                            &resp,
                            Response::ExecResult { exit_code: 0, stdout, .. }
                                if stdout.trim().parse::<u32>().unwrap_or(0) > 0
                        );
                        super::TestOutcome::new(&a, pass, format!("{resp:?}"))
                    })
                })
            });
        }

        // PROC.uptime: /proc/uptime is readable.
        {
            let a = agent_s.clone();
            reg.test("matrix", "proc_filesystem", format!("PROC.uptime.{agent}"))
                .timeout(60)
                .build(move |cx| {
                    let handle = cx.require(agent);
                    Box::new(move |run| {
                        let a = a.clone();
                        Box::pin(async move {
                            let resp = pf_fs_read(run, &handle, "/proc/uptime".into()).await;
                            let pass =
                                matches!(&resp, Response::Ok { data: Some(d) } if !d.is_empty());
                            super::TestOutcome::new(&a, pass, format!("{resp:?}"))
                        })
                    })
                });
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// SK: SIGKILL of a parent agent whose subtree contains SpawnRemote
// (non-PIE) descendants. Reproduces the production hang we hit in
// `cargo test -- 'litebox::PN.B.eof'`: the harness coordinator
// SIGKILLs agent A in teardown, but A's vfork-child stub thread that
// did `wait_worker_host(NP_host_pid)` blocks A's process from being
// reaped because the non-PIE host worker (NP) is never sent a signal.
// The cascading effect is that the coordinator's `Child::wait()` for A
// can hang indefinitely, plus orphan host workers remain alive after
// container shutdown.
//
// Each test spawns its own fresh agent E — independent of the global
// matrix — builds the suspect subtree shape, then SIGKILLs E and
// asserts that the wait completes within a small wall-clock budget.
// On native this is sub-second; under litebox with the platform bug
// unfixed the wait will not return and these tests time out (FAIL).
//
// No `xfail` is recorded: a real FAIL on litebox is the desired
// signal that the underlying platform bug needs fixing. The test
// harness's own teardown is wrapped in a 10-s timeout (commit
// f99cac06), so a FAIL here does not stall the docker container.
// ═══════════════════════════════════════════════════════════════════

/// Wall-clock budget for `Child::wait()` after SIGKILL. Native
/// completes in < 50 ms; we give 5 s to absorb tokio scheduling
/// jitter under heavy parallelism without masking real hangs.
const SK_WAIT_BUDGET_SECS: u64 = 5;

/// Per-test outer budget. Must exceed `SpawnRemote` setup cost
/// (the broker rewrites a 124 MB binary on first use, plus the
/// well-known `spawn_nonpie_subtree` 30-s timeout under litebox).
const SK_TEST_TIMEOUT_SECS: u64 = 90;

pub(crate) fn register_subtree_kill_tests(reg: &mut Registry<'_>) {
    // SK.subtree.direct — SIGKILL E whose immediate child is a
    // non-PIE worker spawned via SpawnRemote. Reproduces the exact
    // shape that hung the PN.B.eof teardown.
    reg.test("matrix", "subtree_kill", "SK.subtree.direct".to_string())
        .timeout(SK_TEST_TIMEOUT_SECS)
        .build(move |cx| {
            let e = cx.require(AgentName::Dpg3);
            let npx = cx.declare_ephemeral(AgentName::Dpg3, "NPx", SpawnKind::NonPie);
            Box::new(move |run| {
                let e = e.clone();
                let npx = npx.clone();
                Box::pin(async move {
                    let _ = crate::nonpie_binary();
                    let r = run.spawn_ephemeral(&npx).await;
                    if !super::ok_spawned_response(&r) {
                        return super::TestOutcome::new(
                            "E",
                            false,
                            format!("setup: spawn_ephemeral(NPx) failed: {r:?}"),
                        );
                    }
                    run_subtree_kill(run, &e).await
                })
            })
        });

    // SK.subtree.deep — SIGKILL E whose subtree is
    // E → EE → NPx (non-PIE leaf). Generalizes the depth axis: tests
    // that the wait4 stub at the *grandchild* level still propagates
    // back when the *root* is SIGKILLed.
    reg.test("matrix", "subtree_kill", "SK.subtree.deep".to_string())
        .timeout(SK_TEST_TIMEOUT_SECS)
        .build(move |cx| {
            let e = cx.require(AgentName::Dpg3);
            let _ee = cx.require(AgentName::Dpg3Dpg);
            // NPx is a non-PIE child of EE, two levels below E.
            let npx = cx.declare_ephemeral(AgentName::Dpg3Dpg, "NPx", SpawnKind::NonPie);
            Box::new(move |run| {
                let e = e.clone();
                let npx = npx.clone();
                Box::pin(async move {
                    let _ = crate::nonpie_binary();
                    // EE was already spawned under E by spawn_tree when
                    // the test declared AgentName::Dpg3Dpg. Ask EE to spawn
                    // its own non-PIE descendant.
                    let r = run.spawn_ephemeral(&npx).await;
                    if !super::ok_spawned_response(&r) {
                        return super::TestOutcome::new(
                            "E",
                            false,
                            format!("setup: spawn_ephemeral(NPx via EE) failed: {r:?}"),
                        );
                    }
                    run_subtree_kill(run, &e).await
                })
            })
        });

    // SK.subtree.exit_then_kill — cooperative Exit on the non-PIE
    // descendant first, then SIGKILL the root. Inverts the timing
    // relative to direct_nonpie: by the time the root is killed, the
    // wait_worker_host stub thread has already seen its host worker
    // exit. SIGKILL+wait should be especially fast. If this also
    // hangs, the bug is in stub-thread cleanup itself, not in
    // worker-exit-signal propagation.
    reg.test(
        "matrix",
        "subtree_kill",
        "SK.subtree.exit_then_kill".to_string(),
    )
    .timeout(SK_TEST_TIMEOUT_SECS)
    .build(move |cx| {
        let e = cx.require(AgentName::Dpg3);
        let npx = cx.declare_ephemeral(AgentName::Dpg3, "NPx", SpawnKind::NonPie);
        Box::new(move |run| {
            let e = e.clone();
            let npx = npx.clone();
            Box::pin(async move {
                let _ = crate::nonpie_binary();
                let r = run.spawn_ephemeral(&npx).await;
                if !super::ok_spawned_response(&r) {
                    return super::TestOutcome::new(
                        "E",
                        false,
                        format!("setup: spawn_ephemeral(NPx) failed: {r:?}"),
                    );
                }
                // Cooperative shutdown of the non-PIE descendant
                // before we kill the root. Forward(Exit) reaches NPx
                // via E. If the response stream desyncs we ignore —
                // the goal is just to make NPx exit.
                let _ = run.forward(&npx, InfraCommand::Exit).await;
                run_subtree_kill(run, &e).await
            })
        })
    });
}

/// SIGKILL the static `E` agent and time how long the wait takes.
/// Returns pass=true iff wait completes within `SK_WAIT_BUDGET_SECS`.
async fn run_subtree_kill(
    cx: &mut super::run_context::RunContext<'_>,
    e: &super::agents::AgentHandle,
) -> super::TestOutcome {
    let budget = Duration::from_secs(SK_WAIT_BUDGET_SECS);
    let result = cx.kill_and_wait(e, budget).await;
    let (pass, detail) = match result {
        Ok(elapsed) => (
            true,
            format!(
                "kill_and_wait Ok elapsed={}ms budget={}s",
                elapsed.as_millis(),
                SK_WAIT_BUDGET_SECS,
            ),
        ),
        Err(elapsed) => (
            false,
            format!(
                "kill_and_wait TIMEOUT elapsed={}ms budget={}s",
                elapsed.as_millis(),
                SK_WAIT_BUDGET_SECS,
            ),
        ),
    };
    super::TestOutcome::new("E", pass, detail)
}
