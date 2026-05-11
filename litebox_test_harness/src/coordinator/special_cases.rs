// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Contamination sequence tests — inherently sequential tests that depend on
//! accumulated per-agent state from prior execs.
//!
//! These cannot be expressed as cross-product loops because each test depends
//! on the state left by the previous exec on the same agent (e.g., "run
//! non-PIE, then run PIE — does the PIE see clean output?").

use super::agents::{AgentHandle, AgentName, EphemeralHandle, SpawnKind};
use super::registry::Registry;
use super::run_context::RunContext;
use crate::handlers::{HandlerCtx, HandlerError, HandlerToken};
use crate::protocol::{Command, Response};
use crate::register_handler;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::process::{Command as StdCommand, Stdio};
use std::time::Duration;

macro_rules! typed_test {
    ($reg:ident, $suite:expr, $group:expr, $id:expr, timeout = $timeout:expr, agents [$($handle:ident = $agent:expr),+ $(,)?], |$run:ident| $body:block) => {{
        $reg.test($suite, $group, $id).timeout($timeout).build(move |cx| {
            $(#[allow(unused_variables)] let $handle = cx.require($agent);)+
            Box::new(move |$run| Box::pin(async move $body))
        });
    }};
    // Variant with both static agents and ephemerals.
    ($reg:ident, $suite:expr, $group:expr, $id:expr, timeout = $timeout:expr,
     agents [$($handle:ident = $agent:expr),+ $(,)?],
     ephemerals [$($eh:ident = ($parent:expr, $label:expr, $kind:expr)),+ $(,)?],
     |$run:ident| $body:block) => {{
        $reg.test($suite, $group, $id).timeout($timeout).build(move |cx| {
            $(#[allow(unused_variables)] let $handle = cx.require($agent);)+
            $(let $eh = cx.declare_ephemeral($parent, $label, $kind);)+
            Box::new(move |$run| Box::pin(async move {
                $(let $eh = $eh.clone();)+
                $body
            }))
        });
    }};
}

#[derive(Serialize, Deserialize)]
struct ExecScriptArgs {
    shell: String,
    script: String,
    timeout_secs: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct ExecScriptOut {
    exit_code: i32,
    stdout: String,
    stderr: String,
}

#[derive(Serialize, Deserialize)]
struct FsWriteArgs {
    path: String,
    data: String,
}

#[derive(Serialize, Deserialize)]
struct FsReadArgs {
    path: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct FsReadOut {
    data: String,
}

#[derive(Serialize, Deserialize)]
struct PathArgs {
    path: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct UnixListenOut {
    path: String,
}

#[derive(Serialize, Deserialize)]
struct UnixConnectArgs {
    path: String,
    data: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ConnectOut {
    echo: String,
}

#[derive(Serialize, Deserialize)]
struct TcpListenArgs {
    port: u16,
}

#[derive(Debug, Serialize, Deserialize)]
struct TcpListenOut {
    port: u16,
}

#[derive(Serialize, Deserialize)]
struct TcpConnectArgs {
    addr: String,
    data: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct SpawnRemoteOut {
    detail: String,
}

const EXEC_SCRIPT: HandlerToken<ExecScriptArgs, ExecScriptOut> =
    HandlerToken::new("special_cases.exec_script");
const FS_WRITE: HandlerToken<FsWriteArgs, ()> = HandlerToken::new("special_cases.fs_write");
const FS_READ: HandlerToken<FsReadArgs, FsReadOut> = HandlerToken::new("special_cases.fs_read");
const UNIX_LISTEN: HandlerToken<PathArgs, UnixListenOut> =
    HandlerToken::new("special_cases.unix_listen");
const UNIX_CONNECT: HandlerToken<UnixConnectArgs, ConnectOut> =
    HandlerToken::new("special_cases.unix_connect");
const TCP_LISTEN: HandlerToken<TcpListenArgs, TcpListenOut> =
    HandlerToken::new("special_cases.tcp_listen");
const TCP_CONNECT: HandlerToken<TcpConnectArgs, ConnectOut> =
    HandlerToken::new("special_cases.tcp_connect");
const SPAWN_REMOTE: HandlerToken<(), SpawnRemoteOut> =
    HandlerToken::new("special_cases.spawn_remote");

async fn handle_exec_script(
    args: ExecScriptArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<ExecScriptOut, HandlerError> {
    let mut child = StdCommand::new(&args.shell)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(args.script.as_bytes())?;
    }
    let output = wait_with_timeout(child, Duration::from_secs(args.timeout_secs))?;
    Ok(ExecScriptOut {
        exit_code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    })
}

async fn handle_fs_write(args: FsWriteArgs, _ctx: &mut HandlerCtx<'_>) -> Result<(), HandlerError> {
    if let Some(parent) = std::path::Path::new(&args.path).parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&args.path, args.data)?;
    Ok(())
}

async fn handle_fs_read(
    args: FsReadArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<FsReadOut, HandlerError> {
    Ok(FsReadOut {
        data: std::fs::read_to_string(args.path)?,
    })
}

async fn handle_unix_listen(
    args: PathArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<UnixListenOut, HandlerError> {
    let _ = std::fs::remove_file(&args.path);
    let listener = std::os::unix::net::UnixListener::bind(&args.path)?;
    let path = args.path.clone();
    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0_u8; 4096];
            if let Ok(n) = stream.read(&mut buf)
                && n > 0
            {
                let _ = stream.write_all(&buf[..n]);
            }
        }
    });
    Ok(UnixListenOut { path })
}

async fn handle_unix_connect(
    args: UnixConnectArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<ConnectOut, HandlerError> {
    let mut stream = std::os::unix::net::UnixStream::connect(args.path)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.write_all(args.data.as_bytes())?;
    stream.flush()?;
    let mut buf = [0_u8; 4096];
    let n = stream.read(&mut buf)?;
    Ok(ConnectOut {
        echo: String::from_utf8_lossy(&buf[..n]).to_string(),
    })
}

async fn handle_tcp_listen(
    args: TcpListenArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<TcpListenOut, HandlerError> {
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, args.port))?;
    let port = listener.local_addr()?.port();
    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0_u8; 4096];
            if let Ok(n) = stream.read(&mut buf)
                && n > 0
            {
                let _ = stream.write_all(&buf[..n]);
            }
        }
    });
    Ok(TcpListenOut { port })
}

async fn handle_tcp_connect(
    args: TcpConnectArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<ConnectOut, HandlerError> {
    let mut stream = std::net::TcpStream::connect(&args.addr)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.write_all(args.data.as_bytes())?;
    stream.flush()?;
    let mut buf = vec![0_u8; args.data.len()];
    stream.read_exact(&mut buf)?;
    Ok(ConnectOut {
        echo: String::from_utf8_lossy(&buf).to_string(),
    })
}

async fn handle_spawn_remote(
    _args: (),
    _ctx: &mut HandlerCtx<'_>,
) -> Result<SpawnRemoteOut, HandlerError> {
    let remote_exe = crate::nonpie_binary();
    let mut child = StdCommand::new(remote_exe)
        .arg("agent")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(b"{\"cmd\":\"exit\"}\n")?;
    }
    let status = child.wait()?;
    if !status.success() {
        return Err(HandlerError(format!("remote child exited with {status}")));
    }
    Ok(SpawnRemoteOut {
        detail: "1 remote children spawned".to_string(),
    })
}

fn wait_with_timeout(
    mut child: std::process::Child,
    timeout: Duration,
) -> Result<std::process::Output, HandlerError> {
    let start = std::time::Instant::now();
    loop {
        if child.try_wait()?.is_some() {
            return child.wait_with_output().map_err(HandlerError::from);
        }
        if start.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(HandlerError(format!(
                "process timed out after {}s (likely deadlocked)",
                timeout.as_secs()
            )));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

async fn forward_named_typed<A, O>(
    run: &mut RunContext<'_>,
    handle: &EphemeralHandle,
    token: &HandlerToken<A, O>,
    args: A,
) -> Result<O, String>
where
    A: Serialize,
    O: serde::de::DeserializeOwned,
{
    let args = serde_json::to_value(args).map_err(|e| format!("args serialize: {e}"))?;
    let resp = run
        .forward(
            handle,
            Command::Run {
                handler: token.name().to_string(),
                args,
            },
        )
        .await;
    match resp {
        Response::Result {
            ok: true,
            data,
            error: _,
        } => serde_json::from_value(data).map_err(|e| format!("typed deserialize: {e}")),
        Response::Result {
            ok: false,
            data: _,
            error,
        } => Err(error.unwrap_or_else(|| "handler failed".into())),
        other => Err(format!("expected Result, got {other:?}")),
    }
}

fn register_special_case_handlers() {
    register_handler!(EXEC_SCRIPT, handle_exec_script);
    register_handler!(FS_WRITE, handle_fs_write);
    register_handler!(FS_READ, handle_fs_read);
    register_handler!(UNIX_LISTEN, handle_unix_listen);
    register_handler!(UNIX_CONNECT, handle_unix_connect);
    register_handler!(TCP_LISTEN, handle_tcp_listen);
    register_handler!(TCP_CONNECT, handle_tcp_connect);
    register_handler!(SPAWN_REMOTE, handle_spawn_remote);
}

fn result_to_response<T>(result: Result<T, String>, ok: impl FnOnce(T) -> Response) -> Response {
    match result {
        Ok(out) => ok(out),
        Err(error) => Response::Error { error },
    }
}

async fn send_spawn_remote_response(run: &mut RunContext<'_>, handle: &AgentHandle) -> Response {
    result_to_response(
        run.send_named_typed(handle, &SPAWN_REMOTE, ()).await,
        |out: SpawnRemoteOut| Response::Ok {
            data: Some(out.detail),
        },
    )
}

async fn send_fs_write_response(
    run: &mut RunContext<'_>,
    handle: &AgentHandle,
    path: String,
    data: String,
) -> Response {
    result_to_response(
        run.send_named_typed(handle, &FS_WRITE, FsWriteArgs { path, data })
            .await,
        |()| Response::Ok { data: None },
    )
}

async fn forward_fs_write_response(
    run: &mut RunContext<'_>,
    handle: &EphemeralHandle,
    path: String,
    data: String,
) -> Response {
    result_to_response(
        forward_named_typed(run, handle, &FS_WRITE, FsWriteArgs { path, data }).await,
        |()| Response::Ok { data: None },
    )
}

async fn send_fs_read_response(
    run: &mut RunContext<'_>,
    handle: &AgentHandle,
    path: String,
) -> Response {
    result_to_response(
        run.send_named_typed(handle, &FS_READ, FsReadArgs { path })
            .await,
        |out: FsReadOut| Response::Ok {
            data: Some(out.data),
        },
    )
}

async fn forward_fs_read_response(
    run: &mut RunContext<'_>,
    handle: &EphemeralHandle,
    path: String,
) -> Response {
    result_to_response(
        forward_named_typed(run, handle, &FS_READ, FsReadArgs { path }).await,
        |out: FsReadOut| Response::Ok {
            data: Some(out.data),
        },
    )
}

async fn send_unix_listen_response(
    run: &mut RunContext<'_>,
    handle: &AgentHandle,
    path: String,
) -> Response {
    result_to_response(
        run.send_named_typed(handle, &UNIX_LISTEN, PathArgs { path })
            .await,
        |out: UnixListenOut| Response::UnixListening { path: out.path },
    )
}

async fn forward_unix_listen_response(
    run: &mut RunContext<'_>,
    handle: &EphemeralHandle,
    path: String,
) -> Response {
    result_to_response(
        forward_named_typed(run, handle, &UNIX_LISTEN, PathArgs { path }).await,
        |out: UnixListenOut| Response::UnixListening { path: out.path },
    )
}

async fn send_unix_connect_response(
    run: &mut RunContext<'_>,
    handle: &AgentHandle,
    path: String,
    data: String,
) -> Response {
    result_to_response(
        run.send_named_typed(handle, &UNIX_CONNECT, UnixConnectArgs { path, data })
            .await,
        |out: ConnectOut| Response::Connected { echo: out.echo },
    )
}

async fn forward_unix_connect_response(
    run: &mut RunContext<'_>,
    handle: &EphemeralHandle,
    path: String,
    data: String,
) -> Response {
    result_to_response(
        forward_named_typed(run, handle, &UNIX_CONNECT, UnixConnectArgs { path, data }).await,
        |out: ConnectOut| Response::Connected { echo: out.echo },
    )
}

async fn send_tcp_listen_response(
    run: &mut RunContext<'_>,
    handle: &AgentHandle,
    port: u16,
) -> Response {
    result_to_response(
        run.send_named_typed(handle, &TCP_LISTEN, TcpListenArgs { port })
            .await,
        |out: TcpListenOut| Response::Listening { port: out.port },
    )
}

async fn forward_tcp_listen_response(
    run: &mut RunContext<'_>,
    handle: &EphemeralHandle,
    port: u16,
) -> Response {
    result_to_response(
        forward_named_typed(run, handle, &TCP_LISTEN, TcpListenArgs { port }).await,
        |out: TcpListenOut| Response::Listening { port: out.port },
    )
}

async fn send_tcp_connect_response(
    run: &mut RunContext<'_>,
    handle: &AgentHandle,
    addr: String,
    data: String,
) -> Response {
    result_to_response(
        run.send_named_typed(handle, &TCP_CONNECT, TcpConnectArgs { addr, data })
            .await,
        |out: ConnectOut| Response::Connected { echo: out.echo },
    )
}

async fn forward_tcp_connect_response(
    run: &mut RunContext<'_>,
    handle: &EphemeralHandle,
    addr: String,
    data: String,
) -> Response {
    result_to_response(
        forward_named_typed(run, handle, &TCP_CONNECT, TcpConnectArgs { addr, data }).await,
        |out: ConnectOut| Response::Connected { echo: out.echo },
    )
}

/// Register netlink tests. Each test is self-contained: one exec + check.
#[allow(clippy::too_many_lines)] // exhaustive registration / runner
pub(super) fn register_netlink(reg: &mut Registry<'_>) {
    let mut self_exe_test =
        |id: &str, subcmd: &str, arg: &str, timeout: u64, check: fn(&str) -> bool| {
            for &bt in crate::BinaryType::ALL {
                let id = format!("{id}.{}", bt.label());
                let subcmd = subcmd.to_string();
                let arg = arg.to_string();
                typed_test!(
                    reg,
                    "matrix",
                    "netlink",
                    id,
                    timeout = 60,
                    agents[a = AgentName::Dpg1],
                    |run| {
                        let self_exe = run.self_exe().to_string();
                        let target = crate::binary_path(bt, &self_exe);
                        let args = vec![target, subcmd, arg];
                        let cmd = if timeout > 0 {
                            super::exec_timeout(args, timeout)
                        } else {
                            super::exec(args)
                        };
                        let resp = run.send(&a, cmd).await;
                        let pass = matches!(
                            &resp,
                            Response::ExecResult { exit_code: 0, stdout, .. } if check(stdout)
                        );
                        super::TestOutcome::new("A", pass, format!("{resp:?}"))
                    }
                );
            }
        };

    self_exe_test("NL1.netlink_socket", "getifaddrs-test", "socket", 0, |s| {
        s.contains("NETLINK_SOCKET_OK")
    });
    self_exe_test("NL2.netlink_bind", "getifaddrs-test", "bind", 0, |s| {
        s.contains("NETLINK_BIND_OK")
    });
    self_exe_test(
        "NL3.netlink_getlink",
        "getifaddrs-test",
        "getlink",
        0,
        |s| s.contains("NETLINK_GETLINK_OK"),
    );
    self_exe_test(
        "NL4.netlink_getaddr",
        "getifaddrs-test",
        "getaddr",
        0,
        |s| s.contains("NETLINK_GETADDR_OK"),
    );
    self_exe_test(
        "NL3b.sendmsg_recvmsg",
        "getifaddrs-test",
        "sendmsg",
        0,
        |s| s.contains("NETLINK_SENDMSG_RECVMSG_OK"),
    );
    self_exe_test(
        "NL3c.double_request",
        "getifaddrs-test",
        "double",
        30,
        |s| s.contains("NETLINK_DOUBLE_OK"),
    );
    self_exe_test(
        "NL3d.peek_trunc",
        "getifaddrs-test",
        "peek-trunc",
        30,
        |s| s.contains("NETLINK_PEEK_TRUNC_OK"),
    );
    self_exe_test("NL5.getifaddrs_full", "getifaddrs-test", "full", 30, |s| {
        s.contains("GETIFADDRS_OK")
    });

    self_exe_test("NL6.mac_address", "unix-socket-test", "mac", 30, |s| {
        s.contains("NL6_MAC_CHECK")
    });

    typed_test!(
        reg,
        "matrix",
        "netlink",
        "X48.node_networkInterfaces",
        timeout = 60,
        agents[a = AgentName::Dpg1],
        |run| {
            let resp = run
            .send(
                &a,
                super::exec_timeout(
                    vec![
                        "/usr/local/bin/node".into(),
                        "-e".into(),
                        "try { const r = require('os').networkInterfaces(); console.log('NETIF_OK:' + Object.keys(r).length); } catch(e) { console.log('NETIF_ERR:' + e.code); }".into(),
                    ],
                    30,
                ),
            )
            .await;
            let pass = matches!(
                &resp,
                Response::ExecResult { exit_code: 0, stdout, .. }
                    if stdout
                        .lines()
                        .find_map(|l| l.strip_prefix("NETIF_OK:"))
                        .and_then(|s| s.trim().parse::<u32>().ok())
                        .is_some_and(|n| n > 0)
            );
            super::TestOutcome::new("A", pass, format!("{resp:?}"))
        }
    );
}

/// Register IPv6 network tests.
pub(super) fn register_net_ipv6(reg: &mut Registry<'_>) {
    let cases: &[(&str, &str)] = &[
        ("NET1.ipv6_socket", "ipv6-socket"),
        ("NET2.ipv6_listen", "ipv6-listen"),
        ("NET4.ipv4_listen", "ipv4-listen"),
        ("NET5.ipv6_getaddrinfo", "ipv6-getaddrinfo"),
        ("NET6.ipv6_v6only", "ipv6-v6only"),
    ];
    for &(name, sub) in cases {
        for &bt in crate::BinaryType::ALL {
            let id = format!("{name}.{}", bt.label());
            let sub = sub.to_string();
            typed_test!(
                reg,
                "matrix",
                "net_ipv6",
                id,
                timeout = 60,
                agents[a = AgentName::Dpg1],
                |run| {
                    let self_exe = run.self_exe().to_string();
                    let target = crate::binary_path(bt, &self_exe);
                    let resp = run
                        .send(
                            &a,
                            super::exec_timeout(vec![target, "net-test".into(), sub], 10),
                        )
                        .await;
                    let pass = matches!(
                        &resp,
                        Response::ExecResult { stdout, .. } if stdout.contains("_OK")
                    );
                    super::TestOutcome::new("A", pass, format!("{resp:?}"))
                }
            );
        }
    }
}

/// Register terminal ioctl tests.
pub(super) fn register_terminal_ioctl(reg: &mut Registry<'_>) {
    let ops = ["tcgets", "tcsets", "tcsetsw", "tcsetsf", "tiocgwinsz"];
    let fds = [0, 1, 2];
    for op in &ops {
        for fd in &fds {
            for &bt in crate::BinaryType::ALL {
                let id = format!("TERM.{op}_fd{fd}.{}", bt.label());
                let op = op.to_string();
                let fd_str = fd.to_string();
                typed_test!(
                    reg,
                    "matrix",
                    "terminal_ioctl",
                    id,
                    timeout = 60,
                    agents[a = AgentName::Dpg1],
                    |run| {
                        let self_exe = run.self_exe().to_string();
                        let target = crate::binary_path(bt, &self_exe);
                        let resp = run
                            .send(
                                &a,
                                super::exec_timeout(
                                    vec![target, "exit-test".into(), "term".into(), op, fd_str],
                                    8,
                                ),
                            )
                            .await;
                        // tcgetattr / tcsetattr / TIOCGWINSZ on a pipe must
                        // return ENOTTY (errno=25). Exec wires stdio to pipes,
                        // so every (op, fd) row should produce TERM_ERR with
                        // errno=25.
                        // Exit code: tcgets/tiocgwinsz return from main (exit 0);
                        // tcsets/tcsetsw/tcsetsf hit the phase=tcgetattr fast-fail
                        // and call process::exit(1).
                        let pass = matches!(
                            &resp,
                            Response::ExecResult { exit_code: 0 | 1, stdout, .. }
                                if stdout.contains("TERM_ERR")
                                    && stdout.contains("errno=25")
                        );
                        super::TestOutcome::new("A", pass, format!("{resp:?}"))
                    }
                );
            }
        }
    }
}

/// Register Node.js exit tests.
pub(super) fn register_node_exit(reg: &mut Registry<'_>) {
    typed_test!(
        reg,
        "fork",
        "node_exit",
        "EX6.node_version_exit",
        timeout = 60,
        agents[a = AgentName::Dpg1],
        |run| {
            let resp = run
                .send(
                    &a,
                    super::exec_timeout(vec!["/usr/local/bin/node".into(), "--version".into()], 10),
                )
                .await;
            let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.starts_with('v'));
            super::TestOutcome::new("A", pass, format!("{resp:?}"))
        }
    );

    typed_test!(
        reg,
        "fork",
        "node_exit",
        "EX7.node_process_exit",
        timeout = 60,
        agents[a = AgentName::Dpg1],
        |run| {
            let resp = run
                .send(
                    &a,
                    super::exec_timeout(
                        vec![
                            "/usr/local/bin/node".into(),
                            "-e".into(),
                            "process.exit(0)".into(),
                        ],
                        10,
                    ),
                )
                .await;
            let pass = matches!(&resp, Response::ExecResult { exit_code: 0, .. });
            super::TestOutcome::new("A", pass, format!("{resp:?}"))
        }
    );

    typed_test!(
        reg,
        "fork",
        "node_exit",
        "EX8.node_exit_code",
        timeout = 60,
        agents[a = AgentName::Dpg1],
        |run| {
            let resp = run
                .send(
                    &a,
                    super::exec_timeout(
                        vec![
                            "/usr/local/bin/node".into(),
                            "-e".into(),
                            "process.exit(42)".into(),
                        ],
                        10,
                    ),
                )
                .await;
            let pass = matches!(&resp, Response::ExecResult { exit_code: 42, .. });
            super::TestOutcome::new("A", pass, format!("{resp:?}"))
        }
    );

    typed_test!(
        reg,
        "fork",
        "node_exit",
        "EX9.node_console_exit",
        timeout = 60,
        agents[a = AgentName::Dpg1],
        |run| {
            let resp = run
                .send(
                    &a,
                    super::exec_timeout(
                        vec![
                            "/usr/local/bin/node".into(),
                            "-e".into(),
                            "console.log(\"NODE_EXIT_OK\")".into(),
                        ],
                        10,
                    ),
                )
                .await;
            let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("NODE_EXIT_OK"));
            super::TestOutcome::new("A", pass, format!("{resp:?}"))
        }
    );
}

/// Register FS I/O matrix tests.
pub(super) fn register_fs_io(reg: &mut Registry<'_>) {
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
                            .send(
                                &a,
                                super::exec_timeout(
                                    vec![target, "fs-test".into(), "io".into(), op, path],
                                    15,
                                ),
                            )
                            .await;
                        let pass = matches!(&resp, Response::ExecResult { stdout, .. } if stdout.contains("FS_OK"));
                        super::TestOutcome::new("A", pass, format!("{resp:?}"))
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
                            .send(
                                &a,
                                super::exec_timeout(
                                    vec![target, "fs-test".into(), mode, bin, path],
                                    30,
                                ),
                            )
                            .await;
                        let pass = matches!(&resp, Response::ExecResult { stdout, .. } if stdout.contains("FS_OK"));
                        super::TestOutcome::new("A", pass, format!("{resp:?}"))
                    }
                );
            }
        }
    }
}

/// Register capture-pipe fork tests.
pub(super) fn register_capture_pipe(reg: &mut Registry<'_>) {
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
                                .send(
                                    &handle,
                                    super::exec_timeout(
                                        vec![target, "capture-pipe".into(), cmd_type, shell],
                                        10,
                                    ),
                                )
                                .await;
                            let pass = matches!(&resp, Response::ExecResult { stdout, .. } if stdout.contains("CP_OK"));
                            super::TestOutcome::new(&agent_label, pass, format!("{resp:?}"))
                        }
                    );
                }
            }
        }
    }
}

/// Register stdin-piped script tests.
pub(super) fn register_stdin_script(reg: &mut Registry<'_>) {
    register_special_case_handlers();
    const SCRIPTS: &[(&str, &str, &str)] = &[
        (
            "cmd_subst",
            "FOO=$(echo hello)\necho FOO=$FOO\necho DONE\n",
            "FOO=hello",
        ),
        (
            "pipe_in_subst",
            "A=$(echo one | cat)\necho A=$A\necho DONE\n",
            "A=one",
        ),
        (
            "multi_pipe_subst",
            "A=$(echo data | grep data | cat)\necho A=$A\necho DONE\n",
            "A=data",
        ),
        (
            "file_pipe_subst",
            "A=$(cat /shared/host_wrote.txt | cat)\necho A=$A\necho DONE\n",
            "A=from_host",
        ),
        (
            "sequential_subst",
            "A=$(echo first)\nB=$(echo second)\necho A=$A B=$B\necho DONE\n",
            "A=first B=second",
        ),
        (
            "subst_then_cmds",
            "A=$(echo val | cat)\necho A=$A\necho LINE1\necho LINE2\necho LINE3\n",
            "A=val",
        ),
        (
            "vscode_osrelease",
            "ID=$(cat /etc/os-release | grep -E '^ID=' | sed 's/ID=//g' | sed 's/\"//g')\necho ID=$ID\necho DONE\n",
            "ID=ubuntu",
        ),
        (
            "backtick_pipe",
            "A=`echo one | cat`\necho A=$A\necho DONE\n",
            "A=one",
        ),
    ];
    const SHELLS: &[&str] = &["sh", "bash"];
    const SS_AGENTS: &[AgentName] = &[AgentName::Dpg1, AgentName::Dpg1Dpg1];

    for &agent in SS_AGENTS {
        for &shell in SHELLS {
            for &(name, script, expected) in SCRIPTS {
                let id = format!("SS.{name}.{shell}.{agent}");
                let agent_name = agent;
                let agent_label = agent.to_string();
                let shell = shell.to_string();
                let script = script.to_string();
                let expected = expected.to_string();
                typed_test!(
                    reg,
                    "shell",
                    "stdin_script",
                    id,
                    timeout = 60,
                    agents[handle = agent_name],
                    |run| {
                        let result = run
                            .send_named_typed(
                                &handle,
                                &EXEC_SCRIPT,
                                ExecScriptArgs {
                                    shell,
                                    script,
                                    timeout_secs: 10,
                                },
                            )
                            .await;
                        let pass = matches!(&result, Ok(out) if out.stdout.contains(&*expected));
                        super::TestOutcome::new(&agent_label, pass, format!("{result:?}"))
                    }
                );
            }
        }
    }
}

#[derive(Clone, Copy)]
enum XsiExpectation {
    Exact {
        exit_code: i32,
        stdout: &'static str,
    },
    NonZero {
        stdout: &'static str,
    },
    Contains {
        exit_code: i32,
        parts: &'static [&'static str],
    },
}

impl XsiExpectation {
    fn matches_exec(self, out: &ExecScriptOut) -> bool {
        match self {
            Self::Exact { exit_code, stdout } => {
                out.exit_code == exit_code && out.stdout == stdout && out.stderr.is_empty()
            }
            Self::NonZero { stdout } => out.exit_code != 0 && out.stdout == stdout,
            Self::Contains { exit_code, parts } => {
                out.exit_code == exit_code
                    && out.stderr.is_empty()
                    && parts.iter().all(|part| out.stdout.contains(part))
            }
        }
    }
}

struct XsiScript {
    name: &'static str,
    script: &'static str,
    expectation: XsiExpectation,
}

const XSI_SCRIPTS: &[XsiScript] = &[
    XsiScript {
        name: "simple",
        script: "echo hello\n",
        expectation: XsiExpectation::Exact {
            exit_code: 0,
            stdout: "hello\n",
        },
    },
    XsiScript {
        name: "multiline_set_e",
        script: "set -e\necho before\nfalse\necho after\n",
        expectation: XsiExpectation::NonZero { stdout: "before\n" },
    },
    XsiScript {
        name: "heredoc_style",
        script: "cat <<'XSI_EOF'\nalpha\nbeta\ngamma\ndelta\nXSI_EOF\nprintf 'done\\n'\n",
        expectation: XsiExpectation::Exact {
            exit_code: 0,
            stdout: "alpha\nbeta\ngamma\ndelta\ndone\n",
        },
    },
    XsiScript {
        name: "fork_exec",
        script: "echo before\nsh -c 'echo child_ok; /bin/true'\ncat /etc/hostname\necho after\n",
        expectation: XsiExpectation::Contains {
            exit_code: 0,
            parts: &["before\n", "child_ok\n", "after\n"],
        },
    },
];

async fn run_xsi_on_agent(
    run: &mut RunContext<'_>,
    handle: &AgentHandle,
    script: &'static XsiScript,
) -> (bool, String) {
    let result = run
        .send_named_typed(
            handle,
            &EXEC_SCRIPT,
            ExecScriptArgs {
                shell: "/bin/sh".into(),
                script: script.script.into(),
                timeout_secs: 10,
            },
        )
        .await;
    let pass = matches!(&result, Ok(out) if script.expectation.matches_exec(out));
    (pass, format!("{result:?}"))
}

async fn run_xsi_on_ephemeral(
    run: &mut RunContext<'_>,
    handle: &EphemeralHandle,
    script: &'static XsiScript,
) -> (bool, String) {
    let result = forward_named_typed(
        run,
        handle,
        &EXEC_SCRIPT,
        ExecScriptArgs {
            shell: "/bin/sh".into(),
            script: script.script.into(),
            timeout_secs: 10,
        },
    )
    .await;
    let pass = matches!(&result, Ok(out) if script.expectation.matches_exec(out));
    (pass, format!("{result:?}"))
}

/// Register protocol-level stdin script tests for `sh < script` workflows.
pub(super) fn register_xsi_stdin_script(reg: &mut Registry<'_>) {
    register_special_case_handlers();
    for script in XSI_SCRIPTS {
        let id = format!("XSI.stdin_script.{}", script.name);
        reg.test("shell", "xsi_stdin_script", id)
            .timeout(60)
            .build(move |cx| {
                let in_process = cx.require(AgentName::Dpg1);
                let depth_two = cx.require(AgentName::Dpg1Dpg1);
                let fork_target = cx.declare_ephemeral(
                    AgentName::Dpg1,
                    format!("XSI_{}", script.name),
                    SpawnKind::Fork {
                        binary: "self",
                        inherit_listen_ports: Vec::new(),
                    },
                );
                Box::new(move |run| {
                    Box::pin(async move {
                        let mut details = Vec::new();
                        let mut pass = true;

                        let (axis_pass, detail) = run_xsi_on_agent(run, &in_process, script).await;
                        pass &= axis_pass;
                        details.push(format!("in_process={axis_pass}:{detail}"));

                        let spawn_resp = run.spawn_ephemeral(&fork_target).await;
                        let fork_spawned = super::ok_spawned_response(&spawn_resp);
                        pass &= fork_spawned;
                        details.push(format!("fork_spawn={fork_spawned}:{spawn_resp:?}"));
                        if fork_spawned {
                            let (axis_pass, detail) =
                                run_xsi_on_ephemeral(run, &fork_target, script).await;
                            pass &= axis_pass;
                            details.push(format!("fork_target={axis_pass}:{detail}"));
                        }

                        let (axis_pass, detail) = run_xsi_on_agent(run, &depth_two, script).await;
                        pass &= axis_pass;
                        details.push(format!("depth2={axis_pass}:{detail}"));

                        super::TestOutcome::new("A+fork+AA", pass, details.join("; "))
                    })
                })
            });
    }
}

// Register unix socket tests.
#[allow(clippy::too_many_lines)] // exhaustive registration / runner
pub(crate) fn register_unix_socket(reg: &mut Registry<'_>) {
    let simple_tests: &[(&str, &str, &str)] = &[
        (
            "US1.cross_process_unix",
            "cross-process",
            "US1_CROSS_PROCESS_OK",
        ),
        ("US2.cross_exec_unix", "cross-exec", "US2_CROSS_EXEC_OK"),
        ("US3.bidirectional_unix", "bidirectional", "US3_BIDI_OK"),
        ("US4.multi_conn_unix", "multi-conn", "US4_MULTI_OK"),
        ("US5.abstract_unix", "abstract", "US5_ABSTRACT_OK"),
        ("VS1.socket_race", "race", "VS1_RACE_OK"),
    ];
    for &(name, sub, expected) in simple_tests {
        for &bt in crate::BinaryType::ALL {
            let id = format!("{name}.{}", bt.label());
            let sub = sub.to_string();
            let expected = expected.to_string();
            typed_test!(
                reg,
                "xworker",
                "unix_socket",
                id,
                timeout = 60,
                agents[a = AgentName::Dpg1],
                |run| {
                    let self_exe = run.self_exe().to_string();
                    let target = crate::binary_path(bt, &self_exe);
                    let resp = run
                        .send(
                            &a,
                            super::exec_timeout(vec![target, "unix-socket-test".into(), sub], 10),
                        )
                        .await;
                    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains(&*expected));
                    super::TestOutcome::new("A", pass, format!("{resp:?}"))
                }
            );
        }
    }

    for &agent in &[AgentName::Dpg1, AgentName::Dpg1Dpg1, AgentName::Dpg2] {
        for &bt in crate::BinaryType::ALL {
            let id = format!("UF.fork_unix.{}.{agent}", bt.label());
            let agent_name = agent;
            let agent_label = agent.to_string();
            typed_test!(
                reg,
                "xworker",
                "unix_socket",
                id,
                timeout = 60,
                agents[handle = agent_name],
                |run| {
                    let self_exe = run.self_exe().to_string();
                    let target = crate::binary_path(bt, &self_exe);
                    let resp = run
                        .send(
                            &handle,
                            super::exec_timeout(
                                vec![target, "unix-socket-test".into(), "cross-process".into()],
                                15,
                            ),
                        )
                        .await;
                    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("US1_CROSS_PROCESS_OK"));
                    super::TestOutcome::new(&agent_label, pass, format!("{resp:?}"))
                }
            );
        }
    }

    // Long-lived agents this fan-out runs in. One slot per
    // BinaryType leg plus the VS-Code-shape transition slots so
    // each fork-parent code path is exercised.
    for &agent in &[
        AgentName::Dpg1,         // PIE-glibc
        AgentName::Dpg1Dpg1,     // PIE-glibc depth-2
        AgentName::Dpg2,         // PIE-glibc sibling subtree
        AgentName::Dpg1Dpg1Dpg1, // PIE-glibc depth-3
        AgentName::Dpg1Dng,      // non-PIE-glibc (node form)
        AgentName::Dpg1DngDng,   // bash → bash (VS Code hot path)
        AgentName::Dpg1DngSpm,   // bash → cli (VS Code hot path)
        AgentName::Dpg1Spg,      // static-PIE-glibc
        AgentName::Dpg1Spm,      // static-PIE-musl (cli form)
        AgentName::Dpg1SpmDng,   // cli → node (VS Code signature)
        AgentName::Dpg1Snm,      // non-PIE-static-musl
    ] {
        for &bt in crate::BinaryType::ALL {
            let agent_name = agent;
            let agent_label = agent.to_string();
            let id = format!("US6.socketpair_write.{}.{agent}", bt.label());
            typed_test!(
                reg,
                "xworker",
                "unix_socket",
                id,
                timeout = 60,
                agents[handle = agent_name],
                |run| {
                    let self_exe = run.self_exe().to_string();
                    let target = crate::binary_path(bt, &self_exe);
                    let resp = run
                        .send(
                            &handle,
                            super::exec_timeout(
                                vec![
                                    target,
                                    "unix-socket-test".into(),
                                    "socketpair-fork-write".into(),
                                ],
                                15,
                            ),
                        )
                        .await;
                    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("US6_SOCKETPAIR_FORK_OK"));
                    super::TestOutcome::new(&agent_label, pass, format!("{resp:?}"))
                }
            );

            let agent_name = agent;
            let agent_label = agent.to_string();
            let id = format!("US6.socketpair_read.{}.{agent}", bt.label());
            typed_test!(
                reg,
                "xworker",
                "unix_socket",
                id,
                timeout = 60,
                agents[handle = agent_name],
                |run| {
                    let self_exe = run.self_exe().to_string();
                    let target = crate::binary_path(bt, &self_exe);
                    let resp = run
                        .send(
                            &handle,
                            super::exec_timeout(
                                vec![
                                    target,
                                    "unix-socket-test".into(),
                                    "socketpair-fork-read".into(),
                                ],
                                15,
                            ),
                        )
                        .await;
                    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("US6R_SOCKETPAIR_FORK_READ_OK"));
                    super::TestOutcome::new(&agent_label, pass, format!("{resp:?}"))
                }
            );
        }
    }

    // Long-lived agents this fan-out runs in. One slot per
    // BinaryType leg plus the VS-Code-shape transition slots so
    // each fork-parent code path is exercised.
    for &agent in &[
        AgentName::Dpg1,         // PIE-glibc
        AgentName::Dpg1Dpg1,     // PIE-glibc depth-2
        AgentName::Dpg2,         // PIE-glibc sibling subtree
        AgentName::Dpg1Dpg1Dpg1, // PIE-glibc depth-3
        AgentName::Dpg1Dng,      // non-PIE-glibc (node form)
        AgentName::Dpg1DngDng,   // bash → bash (VS Code hot path)
        AgentName::Dpg1DngSpm,   // bash → cli (VS Code hot path)
        AgentName::Dpg1Spg,      // static-PIE-glibc
        AgentName::Dpg1Spm,      // static-PIE-musl (cli form)
        AgentName::Dpg1SpmDng,   // cli → node (VS Code signature)
        AgentName::Dpg1Snm,      // non-PIE-static-musl
    ] {
        for &bt in crate::BinaryType::ALL {
            let id = format!("US6.socketpair_exec.{}.{agent}", bt.label());
            let agent_name = agent;
            let agent_label = agent.to_string();
            typed_test!(
                reg,
                "xworker",
                "unix_socket",
                id,
                timeout = 60,
                agents[handle = agent_name],
                |run| {
                    let self_exe = run.self_exe().to_string();
                    let target = crate::binary_path(bt, &self_exe);
                    let resp = run
                        .send(
                            &handle,
                            super::exec_timeout(
                                vec![target, "unix-socket-test".into(), "socketpair-exec".into()],
                                30,
                            ),
                        )
                        .await;
                    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("US6E_SOCKETPAIR_EXEC_OK"));
                    super::TestOutcome::new(&agent_label, pass, format!("{resp:?}"))
                }
            );
        }
    }
}

// Register cross-worker tests.
#[allow(clippy::too_many_lines)] // exhaustive registration / runner
pub(crate) fn register_cross_worker(reg: &mut Registry<'_>) {
    register_special_case_handlers();
    typed_test!(
        reg,
        "xworker",
        "cross_worker",
        "XW.spawn_remote",
        timeout = 60,
        agents[a = AgentName::Dpg1],
        |run| {
            let resp = send_spawn_remote_response(run, &a).await;
            let pass = super::ok_data_contains(&resp, "remote children spawned");
            super::TestOutcome::new("A", pass, format!("{resp:?}"))
        }
    );

    typed_test!(
        reg,
        "xworker",
        "cross_worker",
        "XW1.remote_write",
        timeout = 60,
        agents[a = AgentName::Dpg1],
        ephemerals[r = (AgentName::Dpg1, "R", SpawnKind::NonPie)],
        |run| {
            let _ = run.spawn_ephemeral(&r).await;
            let resp = forward_fs_write_response(
                run,
                &r,
                "/tmp/xw1.txt".to_string(),
                "REMOTE_DATA".to_string(),
            )
            .await;
            let pass = super::ok_without_data(&resp);
            super::TestOutcome::new("A", pass, format!("{resp:?}"))
        }
    );

    typed_test!(
        reg,
        "xworker",
        "cross_worker",
        "XW1.local_read",
        timeout = 60,
        agents[a = AgentName::Dpg1],
        ephemerals[r = (AgentName::Dpg1, "R", SpawnKind::NonPie)],
        |run| {
            let _ = run.spawn_ephemeral(&r).await;
            let setup_resp = forward_fs_write_response(
                run,
                &r,
                "/tmp/xw1.txt".to_string(),
                "REMOTE_DATA".to_string(),
            )
            .await;
            if !super::ok_without_data(&setup_resp) {
                return super::TestOutcome::new(
                    "A",
                    false,
                    format!("write setup failed: {setup_resp:?}"),
                );
            }
            let resp = send_fs_read_response(run, &a, "/tmp/xw1.txt".to_string()).await;
            let pass = matches!(&resp, Response::Ok { data: Some(d), .. } if d == "REMOTE_DATA");
            super::TestOutcome::new("A", pass, format!("{resp:?}"))
        }
    );

    typed_test!(
        reg,
        "xworker",
        "cross_worker",
        "XW2.local_write",
        timeout = 60,
        agents[a = AgentName::Dpg1],
        |run| {
            let resp = send_fs_write_response(
                run,
                &a,
                "/tmp/xw2.txt".to_string(),
                "LOCAL_DATA".to_string(),
            )
            .await;
            let pass = super::ok_without_data(&resp);
            super::TestOutcome::new("A", pass, format!("{resp:?}"))
        }
    );

    typed_test!(
        reg,
        "xworker",
        "cross_worker",
        "XW2.remote_read",
        timeout = 60,
        agents[a = AgentName::Dpg1],
        ephemerals[r = (AgentName::Dpg1, "R", SpawnKind::NonPie)],
        |run| {
            let _ = run.spawn_ephemeral(&r).await;
            let setup_resp = send_fs_write_response(
                run,
                &a,
                "/tmp/xw2.txt".to_string(),
                "LOCAL_DATA".to_string(),
            )
            .await;
            if !super::ok_without_data(&setup_resp) {
                return super::TestOutcome::new(
                    "A",
                    false,
                    format!("write setup failed: {setup_resp:?}"),
                );
            }
            let resp = forward_fs_read_response(run, &r, "/tmp/xw2.txt".to_string()).await;
            let pass = matches!(&resp, Response::Ok { data: Some(d), .. } if d == "LOCAL_DATA");
            super::TestOutcome::new("A", pass, format!("{resp:?}"))
        }
    );

    typed_test!(
        reg,
        "xworker",
        "cross_worker",
        "XW3.remote_listen",
        timeout = 60,
        agents[a = AgentName::Dpg1],
        ephemerals[r = (AgentName::Dpg1, "R", SpawnKind::NonPie)],
        |run| {
            let _ = run.spawn_ephemeral(&r).await;
            let resp = forward_unix_listen_response(run, &r, "/tmp/xw3.sock".to_string()).await;
            let pass = super::expect_unix_listening_path(&resp, "/tmp/xw3.sock").is_ok();
            super::TestOutcome::new("A", pass, format!("{resp:?}"))
        }
    );

    typed_test!(
        reg,
        "xworker",
        "cross_worker",
        "XW3.local_connect",
        timeout = 60,
        agents[a = AgentName::Dpg1],
        ephemerals[r = (AgentName::Dpg1, "R", SpawnKind::NonPie)],
        |run| {
            let _ = run.spawn_ephemeral(&r).await;
            let listen_resp =
                forward_unix_listen_response(run, &r, "/tmp/xw3c.sock".to_string()).await;
            if super::expect_unix_listening_path(&listen_resp, "/tmp/xw3c.sock").is_err() {
                return super::TestOutcome::new(
                    "A",
                    false,
                    format!("listen setup failed: {listen_resp:?}"),
                );
            }
            let resp = send_unix_connect_response(
                run,
                &a,
                "/tmp/xw3c.sock".to_string(),
                "XW_HELLO".to_string(),
            )
            .await;
            let pass = matches!(&resp, Response::Connected { echo } if echo.contains("XW_HELLO"));
            super::TestOutcome::new("A", pass, format!("{resp:?}"))
        }
    );

    typed_test!(
        reg,
        "xworker",
        "cross_worker",
        "XW4.local_listen",
        timeout = 60,
        agents[a = AgentName::Dpg1],
        |run| {
            let resp = send_unix_listen_response(run, &a, "/tmp/xw4.sock".to_string()).await;
            let pass = super::expect_unix_listening_path(&resp, "/tmp/xw4.sock").is_ok();
            super::TestOutcome::new("A", pass, format!("{resp:?}"))
        }
    );

    typed_test!(
        reg,
        "xworker",
        "cross_worker",
        "XW4.remote_connect",
        timeout = 60,
        agents[a = AgentName::Dpg1],
        ephemerals[r = (AgentName::Dpg1, "R", SpawnKind::NonPie)],
        |run| {
            let _ = run.spawn_ephemeral(&r).await;
            let listen_resp =
                send_unix_listen_response(run, &a, "/tmp/xw4c.sock".to_string()).await;
            if super::expect_unix_listening_path(&listen_resp, "/tmp/xw4c.sock").is_err() {
                return super::TestOutcome::new(
                    "A",
                    false,
                    format!("listen setup failed: {listen_resp:?}"),
                );
            }
            let resp = forward_unix_connect_response(
                run,
                &r,
                "/tmp/xw4c.sock".to_string(),
                "XW_HELLO2".to_string(),
            )
            .await;
            let pass = matches!(&resp, Response::Connected { echo } if echo.contains("XW_HELLO2"));
            super::TestOutcome::new("A", pass, format!("{resp:?}"))
        }
    );

    typed_test!(
        reg,
        "xworker",
        "cross_worker",
        "XW5.remote_tcp_listen",
        timeout = 60,
        agents[a = AgentName::Dpg1],
        ephemerals[r = (AgentName::Dpg1, "R", SpawnKind::NonPie)],
        |run| {
            let _ = run.spawn_ephemeral(&r).await;
            let resp = forward_tcp_listen_response(run, &r, 0).await;
            let pass = super::expect_listening_port(&resp, 0).is_ok();
            super::TestOutcome::new("A", pass, format!("{resp:?}"))
        }
    );

    typed_test!(
        reg,
        "xworker",
        "cross_worker",
        "XW5.local_tcp_connect",
        timeout = 60,
        agents[a = AgentName::Dpg1],
        ephemerals[r = (AgentName::Dpg1, "R", SpawnKind::NonPie)],
        |run| {
            let _ = run.spawn_ephemeral(&r).await;
            let listen_resp = forward_tcp_listen_response(run, &r, 0).await;
            let port = match super::expect_listening_port(&listen_resp, 0) {
                Ok(port) => port,
                Err(e) => {
                    return super::TestOutcome::new(
                        "A",
                        false,
                        format!("listen setup failed: {e}; resp={listen_resp:?}"),
                    );
                }
            };
            let resp = send_tcp_connect_response(
                run,
                &a,
                format!("127.0.0.1:{port}"),
                "XW_TCP_HELLO".to_string(),
            )
            .await;
            let pass =
                matches!(&resp, Response::Connected { echo } if echo.contains("XW_TCP_HELLO"));
            super::TestOutcome::new("A", pass, format!("{resp:?}"))
        }
    );

    typed_test!(
        reg,
        "xworker",
        "cross_worker",
        "XW6.local_tcp_listen",
        timeout = 60,
        agents[a = AgentName::Dpg1],
        |run| {
            let resp = send_tcp_listen_response(run, &a, 0).await;
            let pass = super::expect_listening_port(&resp, 0).is_ok();
            super::TestOutcome::new("A", pass, format!("{resp:?}"))
        }
    );

    typed_test!(
        reg,
        "xworker",
        "cross_worker",
        "XW6.remote_tcp_connect",
        timeout = 60,
        agents[a = AgentName::Dpg1],
        ephemerals[r = (AgentName::Dpg1, "R", SpawnKind::NonPie)],
        |run| {
            let _ = run.spawn_ephemeral(&r).await;
            let listen_resp = send_tcp_listen_response(run, &a, 0).await;
            let port = match super::expect_listening_port(&listen_resp, 0) {
                Ok(port) => port,
                Err(e) => {
                    return super::TestOutcome::new(
                        "A",
                        false,
                        format!("listen setup failed: {e}; resp={listen_resp:?}"),
                    );
                }
            };
            let resp = forward_tcp_connect_response(
                run,
                &r,
                format!("127.0.0.1:{port}"),
                "XW_TCP_HELLO2".to_string(),
            )
            .await;
            let pass =
                matches!(&resp, Response::Connected { echo } if echo.contains("XW_TCP_HELLO2"));
            super::TestOutcome::new("A", pass, format!("{resp:?}"))
        }
    );

    typed_test!(
        reg,
        "xworker",
        "cross_worker",
        "XW7.dpg1_dng_listen",
        timeout = 60,
        agents[d4 = AgentName::Dpg1Dng],
        |run| {
            let resp = send_unix_listen_response(run, &d4, "/tmp/xw7.sock".to_string()).await;
            let pass = super::expect_unix_listening_path(&resp, "/tmp/xw7.sock").is_ok();
            super::TestOutcome::new(AgentName::Dpg1Dng.name(), pass, format!("{resp:?}"))
        }
    );

    typed_test!(reg, "xworker", "cross_worker", "XW7.dpg1_dpg1_dpg1_connect", timeout = 60, agents [d4 = AgentName::Dpg1Dng, d3 = AgentName::Dpg1Dpg1Dpg1], |run| {
        let listen_resp = send_unix_listen_response(run, &d4, "/tmp/xw7c.sock".to_string()).await;
        if super::expect_unix_listening_path(&listen_resp, "/tmp/xw7c.sock").is_err() {
            return super::TestOutcome::new(AgentName::Dpg1Dpg1Dpg1.name(), false, format!("listen setup failed: {listen_resp:?}"));
        }
        let resp = send_unix_connect_response(
            run,
            &d3,
            "/tmp/xw7c.sock".to_string(),
            "XW7_D3_TO_D4".to_string(),
        )
        .await;
        let pass = matches!(&resp, Response::Connected { echo } if echo.contains("XW7_D3_TO_D4"));
        super::TestOutcome::new(AgentName::Dpg1Dpg1Dpg1.name(), pass, format!("{resp:?}"))
    });

    typed_test!(
        reg,
        "xworker",
        "cross_worker",
        "XW8.dpg1_dpg1_dpg1_listen",
        timeout = 60,
        agents[d3 = AgentName::Dpg1Dpg1Dpg1],
        |run| {
            let resp = send_unix_listen_response(run, &d3, "/tmp/xw8.sock".to_string()).await;
            let pass = super::expect_unix_listening_path(&resp, "/tmp/xw8.sock").is_ok();
            super::TestOutcome::new(AgentName::Dpg1Dpg1Dpg1.name(), pass, format!("{resp:?}"))
        }
    );

    typed_test!(reg, "xworker", "cross_worker", "XW8.dpg1_dng_connect", timeout = 60, agents [d3 = AgentName::Dpg1Dpg1Dpg1, d4 = AgentName::Dpg1Dng], |run| {
        let listen_resp = send_unix_listen_response(run, &d3, "/tmp/xw8c.sock".to_string()).await;
        if super::expect_unix_listening_path(&listen_resp, "/tmp/xw8c.sock").is_err() {
            return super::TestOutcome::new(AgentName::Dpg1Dng.name(), false, format!("listen setup failed: {listen_resp:?}"));
        }
        let resp = send_unix_connect_response(
            run,
            &d4,
            "/tmp/xw8c.sock".to_string(),
            "XW8_D4_TO_D3".to_string(),
        )
        .await;
        let pass = matches!(&resp, Response::Connected { echo } if echo.contains("XW8_D4_TO_D3"));
        super::TestOutcome::new(AgentName::Dpg1Dng.name(), pass, format!("{resp:?}"))
    });

    typed_test!(
        reg,
        "xworker",
        "cross_worker",
        "XW9.dpg1_dng_listen",
        timeout = 60,
        agents[d4 = AgentName::Dpg1Dng],
        |run| {
            let resp = send_unix_listen_response(run, &d4, "/tmp/xw9.sock".to_string()).await;
            let pass = super::expect_unix_listening_path(&resp, "/tmp/xw9.sock").is_ok();
            super::TestOutcome::new(AgentName::Dpg1Dng.name(), pass, format!("{resp:?}"))
        }
    );

    typed_test!(reg, "xworker", "cross_worker", "XW9.dpg1_dpg1_connect", timeout = 60, agents [d4 = AgentName::Dpg1Dng, aa = AgentName::Dpg1Dpg1], |run| {
        let listen_resp = send_unix_listen_response(run, &d4, "/tmp/xw9c.sock".to_string()).await;
        if super::expect_unix_listening_path(&listen_resp, "/tmp/xw9c.sock").is_err() {
            return super::TestOutcome::new(AgentName::Dpg1Dpg1.name(), false, format!("listen setup failed: {listen_resp:?}"));
        }
        let resp = send_unix_connect_response(
            run,
            &aa,
            "/tmp/xw9c.sock".to_string(),
            "XW9_AA_TO_D4".to_string(),
        )
        .await;
        let pass = matches!(&resp, Response::Connected { echo } if echo.contains("XW9_AA_TO_D4"));
        super::TestOutcome::new(AgentName::Dpg1Dpg1.name(), pass, format!("{resp:?}"))
    });

    typed_test!(
        reg,
        "xworker",
        "cross_worker",
        "XW10.dpg1_dpg1_dpg1_tcp_listen",
        timeout = 60,
        agents[d3 = AgentName::Dpg1Dpg1Dpg1],
        |run| {
            let resp = send_tcp_listen_response(run, &d3, 0).await;
            let pass = super::expect_listening_port(&resp, 0).is_ok();
            super::TestOutcome::new(AgentName::Dpg1Dpg1Dpg1.name(), pass, format!("{resp:?}"))
        }
    );

    typed_test!(reg, "xworker", "cross_worker", "XW10.dpg2_tcp_connect", timeout = 60, agents [d3 = AgentName::Dpg1Dpg1Dpg1, b = AgentName::Dpg2], |run| {
        let listen_resp = send_tcp_listen_response(run, &d3, 0).await;
        let port = match super::expect_listening_port(&listen_resp, 0) {
            Ok(port) => port,
            Err(e) => return super::TestOutcome::new("B", false, format!("listen setup failed: {e}; resp={listen_resp:?}")),
        };
        let resp = send_tcp_connect_response(
            run,
            &b,
            format!("127.0.0.1:{port}"),
            "XW10_CROSS_SUBTREE".to_string(),
        )
        .await;
        let pass = matches!(&resp, Response::Connected { echo } if echo.contains("XW10_CROSS_SUBTREE"));
        super::TestOutcome::new("B", pass, format!("{resp:?}"))
    });

    typed_test!(
        reg,
        "xworker",
        "cross_worker",
        "XW11.dpg1_dpg1_dpg1_tcp_listen",
        timeout = 60,
        agents[d3 = AgentName::Dpg1Dpg1Dpg1],
        |run| {
            let resp = send_tcp_listen_response(run, &d3, 0).await;
            let pass = super::expect_listening_port(&resp, 0).is_ok();
            super::TestOutcome::new(AgentName::Dpg1Dpg1Dpg1.name(), pass, format!("{resp:?}"))
        }
    );

    typed_test!(
        reg,
        "xworker",
        "cross_worker",
        "XW11.spawn_r2",
        timeout = 60,
        agents[b = AgentName::Dpg2],
        ephemerals[r2 = (AgentName::Dpg2, "R2", SpawnKind::NonPie)],
        |run| {
            let resp = run.spawn_ephemeral(&r2).await;
            let pass = super::ok_spawned_response(&resp);
            super::TestOutcome::new("B", pass, format!("{resp:?}"))
        }
    );

    typed_test!(
        reg,
        "xworker",
        "cross_worker",
        "XW11.r2_tcp_connect",
        timeout = 60,
        agents[d3 = AgentName::Dpg1Dpg1Dpg1, b = AgentName::Dpg2],
        ephemerals[r2 = (AgentName::Dpg2, "R2", SpawnKind::NonPie)],
        |run| {
            let listen_resp = send_tcp_listen_response(run, &d3, 0).await;
            let port = match super::expect_listening_port(&listen_resp, 0) {
                Ok(port) => port,
                Err(e) => return super::TestOutcome::new("R2", false, format!("listen setup failed: {e}; resp={listen_resp:?}")),
            };
            let _ = run.spawn_ephemeral(&r2).await;
            let resp = forward_tcp_connect_response(
                run,
                &r2,
                format!("127.0.0.1:{port}"),
                "XW11_LATE_SPAWN".to_string(),
            )
            .await;
            let pass = matches!(&resp, Response::Connected { echo } if echo.contains("XW11_LATE_SPAWN"));
            super::TestOutcome::new("R2", pass, format!("{resp:?}"))
        }
    );
}

// Register pipe EOF tests.
pub(crate) fn register_pipe_eof(reg: &mut Registry<'_>) {
    // Long-lived agents this fan-out runs in. One slot per
    // BinaryType leg plus the VS-Code-shape transition slots so
    // each fork-parent code path is exercised.
    for &agent in &[
        AgentName::Dpg1,         // PIE-glibc
        AgentName::Dpg1Dpg1,     // PIE-glibc depth-2
        AgentName::Dpg2,         // PIE-glibc sibling subtree
        AgentName::Dpg1Dpg1Dpg1, // PIE-glibc depth-3
        AgentName::Dpg1Dng,      // non-PIE-glibc (node form)
        AgentName::Dpg1DngDng,   // bash → bash (VS Code hot path)
        AgentName::Dpg1DngSpm,   // bash → cli (VS Code hot path)
        AgentName::Dpg1Spg,      // static-PIE-glibc
        AgentName::Dpg1Spm,      // static-PIE-musl (cli form)
        AgentName::Dpg1SpmDng,   // cli → node (VS Code signature)
        AgentName::Dpg1Snm,      // non-PIE-static-musl
    ] {
        for &bt in crate::BinaryType::ALL {
            let id = format!("P1.pipe_eof_fork.{}.{agent}", bt.label());
            let agent_name = agent;
            let agent_label = agent.to_string();
            typed_test!(
                reg,
                "xworker",
                "pipe_eof",
                id,
                timeout = 60,
                agents[handle = agent_name],
                |run| {
                    let self_exe = run.self_exe().to_string();
                    let target = crate::binary_path(bt, &self_exe);
                    let resp = run
                        .send(
                            &handle,
                            super::exec_timeout(
                                vec![target, "pipe-test".into(), "eof-fork".into()],
                                20,
                            ),
                        )
                        .await;
                    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("P1_EOF_OK"));
                    super::TestOutcome::new(&agent_label, pass, format!("{resp:?}"))
                }
            );
        }
    }

    for &agent in &[AgentName::Dpg1, AgentName::Dpg1Dpg1, AgentName::Dpg2] {
        for &bt in crate::BinaryType::ALL {
            let id = format!("P2.pipe_eof_exec.{}.{agent}", bt.label());
            let agent_name = agent;
            let agent_label = agent.to_string();
            typed_test!(
                reg,
                "xworker",
                "pipe_eof",
                id,
                timeout = 60,
                agents[handle = agent_name],
                |run| {
                    let self_exe = run.self_exe().to_string();
                    let target = crate::binary_path(bt, &self_exe);
                    let resp = run
                        .send(
                            &handle,
                            super::exec_timeout(
                                vec![self_exe, "pipe-test".into(), "eof-exec".into(), target],
                                20,
                            ),
                        )
                        .await;
                    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("P2_EOF_OK"));
                    super::TestOutcome::new(&agent_label, pass, format!("{resp:?}"))
                }
            );
        }
    }
}

// Register contamination sequence tests (X49-X59).
#[allow(clippy::too_many_lines)] // exhaustive registration / runner
pub(crate) fn register_contamination_sequence(reg: &mut Registry<'_>) {
    typed_test!(
        reg,
        "contamination",
        "contamination_sequence",
        "X49a.pie_sequential_1",
        timeout = 60,
        agents[a = AgentName::Dpg1],
        |run| {
            let self_exe = run.self_exe().to_string();
            let resp = run
                .send(&a, super::exec(vec![self_exe, "echo-test".into()]))
                .await;
            let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.trim() == "ECHO_TEST_OK");
            super::TestOutcome::new("A", pass, format!("{resp:?}"))
        }
    );

    typed_test!(
        reg,
        "contamination",
        "contamination_sequence",
        "X49b.pie_sequential_2",
        timeout = 60,
        agents[a = AgentName::Dpg1],
        |run| {
            let self_exe = run.self_exe().to_string();
            let resp = run
                .send(
                    &a,
                    super::exec(vec![self_exe, "exit-with".into(), "0".into()]),
                )
                .await;
            let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.is_empty());
            super::TestOutcome::new("A", pass, format!("{resp:?}"))
        }
    );

    typed_test!(
        reg,
        "contamination",
        "contamination_sequence",
        "X50a.nonpie_then_pie_1",
        timeout = 60,
        agents[a = AgentName::Dpg1],
        |run| {
            let nonpie = crate::nonpie_binary();
            let resp = run
                .send(&a, super::exec(vec![nonpie, "echo-test".into()]))
                .await;
            let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("ECHO_TEST_OK"));
            super::TestOutcome::new("A", pass, format!("{resp:?}"))
        }
    );

    typed_test!(
        reg,
        "contamination",
        "contamination_sequence",
        "X50b.nonpie_then_pie_2",
        timeout = 60,
        agents[a = AgentName::Dpg1],
        |run| {
            let self_exe = run.self_exe().to_string();
            let resp = run
                .send(&a, super::exec(vec![self_exe, "echo-test".into()]))
                .await;
            let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.trim() == "ECHO_TEST_OK");
            super::TestOutcome::new("A", pass, format!("{resp:?}"))
        }
    );

    typed_test!(
        reg,
        "contamination",
        "contamination_sequence",
        "X51.nonpie_fresh_agent",
        timeout = 60,
        agents[b = AgentName::Dpg2],
        |run| {
            let nonpie = crate::nonpie_binary();
            let resp = run
                .send(&b, super::exec(vec![nonpie, "echo-test".into()]))
                .await;
            let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("ECHO_TEST_OK"));
            super::TestOutcome::new("B", pass, format!("{resp:?}"))
        }
    );

    typed_test!(
        reg,
        "contamination",
        "contamination_sequence",
        "X52a.B_nonpie_then_pie",
        timeout = 60,
        agents[b = AgentName::Dpg2],
        |run| {
            let self_exe = run.self_exe().to_string();
            let resp = run
                .send(&b, super::exec(vec![self_exe, "echo-test".into()]))
                .await;
            let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.trim() == "ECHO_TEST_OK");
            super::TestOutcome::new("B", pass, format!("{resp:?}"))
        }
    );

    typed_test!(
        reg,
        "contamination",
        "contamination_sequence",
        "X52b.B_pie_after_nonpie",
        timeout = 60,
        agents[b = AgentName::Dpg2],
        |run| {
            let self_exe = run.self_exe().to_string();
            let resp = run
                .send(
                    &b,
                    super::exec(vec![self_exe, "exit-with".into(), "0".into()]),
                )
                .await;
            let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.is_empty());
            super::TestOutcome::new("B", pass, format!("{resp:?}"))
        }
    );

    typed_test!(
        reg,
        "contamination",
        "contamination_sequence",
        "X52c.B_third_exec",
        timeout = 60,
        agents[b = AgentName::Dpg2],
        |run| {
            let self_exe = run.self_exe().to_string();
            let resp = run
                .send(&b, super::exec(vec![self_exe, "echo-test".into()]))
                .await;
            let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.trim() == "ECHO_TEST_OK");
            super::TestOutcome::new("B", pass, format!("{resp:?}"))
        }
    );

    typed_test!(
        reg,
        "contamination",
        "contamination_sequence",
        "X53.stress_pie",
        timeout = 60,
        agents[ab = AgentName::Dpg1Dpg2],
        |run| {
            let self_exe = run.self_exe().to_string();
            for i in 0..30 {
                let resp = run
                    .send(&ab, super::exec(vec![self_exe.clone(), "echo-test".into()]))
                    .await;
                let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.trim() == "ECHO_TEST_OK");
                if !pass {
                    return super::TestOutcome::new(
                        "AB",
                        false,
                        format!("failed at iteration {i}: {resp:?}"),
                    );
                }
            }
            super::TestOutcome::new("AB", true, "30 sequential PIE execs all passed")
        }
    );

    typed_test!(
        reg,
        "contamination",
        "contamination_sequence",
        "X54.nonpie_after_stress",
        timeout = 60,
        agents[ab = AgentName::Dpg1Dpg2],
        |run| {
            let nonpie = crate::nonpie_binary();
            let resp = run
                .send(&ab, super::exec(vec![nonpie, "echo-test".into()]))
                .await;
            let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("ECHO_TEST_OK"));
            super::TestOutcome::new("AB", pass, format!("{resp:?}"))
        }
    );

    typed_test!(
        reg,
        "contamination",
        "contamination_sequence",
        "X55a.one_pie_first",
        timeout = 60,
        agents[aab = AgentName::Dpg1Dpg1Dpg2],
        |run| {
            let self_exe = run.self_exe().to_string();
            let resp = run
                .send(&aab, super::exec(vec![self_exe, "echo-test".into()]))
                .await;
            let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.trim() == "ECHO_TEST_OK");
            super::TestOutcome::new("AAB", pass, format!("{resp:?}"))
        }
    );

    typed_test!(
        reg,
        "contamination",
        "contamination_sequence",
        "X55b.nonpie_second",
        timeout = 60,
        agents[aab = AgentName::Dpg1Dpg1Dpg2],
        |run| {
            let nonpie = crate::nonpie_binary();
            let resp = run
                .send(&aab, super::exec(vec![nonpie, "echo-test".into()]))
                .await;
            let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("ECHO_TEST_OK"));
            super::TestOutcome::new("AAB", pass, format!("{resp:?}"))
        }
    );

    typed_test!(
        reg,
        "contamination",
        "contamination_sequence",
        "X56.second_nonpie_on_B",
        timeout = 60,
        agents[b = AgentName::Dpg2],
        |run| {
            let nonpie = crate::nonpie_binary();
            let resp = run
                .send(&b, super::exec(vec![nonpie, "echo-test".into()]))
                .await;
            let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("ECHO_TEST_OK"));
            super::TestOutcome::new("B", pass, format!("{resp:?}"))
        }
    );

    typed_test!(
        reg,
        "contamination",
        "contamination_sequence",
        "X57.pipe_churn_then_nonpie",
        timeout = 60,
        agents[b = AgentName::Dpg2],
        |run| {
            let nonpie = crate::nonpie_binary();
            for _ in 0..20 {
                let _ = run
                    .send(
                        &b,
                        super::exec(vec![
                            "bash".into(),
                            "-c".into(),
                            "echo churn >/dev/null".into(),
                        ]),
                    )
                    .await;
            }
            let resp = run
                .send(&b, super::exec(vec![nonpie, "echo-test".into()]))
                .await;
            let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("ECHO_TEST_OK"));
            super::TestOutcome::new("B", pass, format!("{resp:?}"))
        }
    );

    typed_test!(
        reg,
        "contamination",
        "contamination_sequence",
        "X58.alternating_pie_nonpie",
        timeout = 60,
        agents[b = AgentName::Dpg2],
        |run| {
            let self_exe = run.self_exe().to_string();
            let nonpie = crate::nonpie_binary();
            let mut results: Vec<(String, bool)> = Vec::new();
            for _ in 0..2 {
                let resp = run
                    .send(&b, super::exec(vec![self_exe.clone(), "echo-test".into()]))
                    .await;
                let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.trim() == "ECHO_TEST_OK");
                results.push((format!("{resp:?}"), pass));

                let resp = run
                    .send(&b, super::exec(vec![nonpie.clone(), "echo-test".into()]))
                    .await;
                let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("ECHO_TEST_OK"));
                results.push((format!("{resp:?}"), pass));
            }
            let all_pass = results.iter().all(|(_, p)| *p);
            let detail = results
                .iter()
                .enumerate()
                .map(|(i, (d, p))| format!("[{i}]={p}: {d}"))
                .collect::<Vec<_>>()
                .join("; ");
            super::TestOutcome::new("B", all_pass, detail)
        }
    );

    typed_test!(
        reg,
        "contamination",
        "contamination_sequence",
        "X59.sequential_nonpie",
        timeout = 60,
        agents[b = AgentName::Dpg2],
        |run| {
            let nonpie = crate::nonpie_binary();
            for i in 0..5 {
                let resp = run
                    .send(&b, super::exec(vec![nonpie.clone(), "echo-test".into()]))
                    .await;
                let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("ECHO_TEST_OK"));
                if !pass {
                    return super::TestOutcome::new(
                        "B",
                        false,
                        format!("failed at iteration {i}: {resp:?}"),
                    );
                }
            }
            super::TestOutcome::new("B", true, "5 sequential non-PIE execs all passed")
        }
    );
}
