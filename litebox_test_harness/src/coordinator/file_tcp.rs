// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! FT (File+TCP) tests — combined file I/O and TCP operations.
//!
//! These tests reproduce the 9P deadlock found via GDB: when an agent
//! has active TCP sockets and tries to open/read a file, the file I/O
//! must not block TCP progress. The family is migrated to handler
//! dispatch so TCP and file operations happen directly in handler bodies.

use std::os::fd::AsRawFd;
use std::thread::JoinHandle;

use serde::{Deserialize, Serialize};

use crate::handlers::{HandlerCtx, HandlerError, HandlerToken};
use crate::os::socket::TcpSocket;
use crate::register_handler;

use super::agents::{AgentHandle, AgentName};
use super::registry::Registry;
use super::run_context::RunContext;

const TEST_FILE: &str = "/tmp/ft_test.txt";
const TEST_DATA: &str = "file_tcp_test_data_1234567890";
const SENDFILE_SOURCE: &str = "/root/litebox_ft_sendfile_source.bin";

#[derive(Serialize, Deserialize, Debug)]
struct DetailOut {
    detail: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct ListenWriteArgs {
    port: u16,
    path: String,
    data: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct ListenReadArgs {
    port: u16,
    path: String,
    prewrite: Option<String>,
    expected: ReadExpectation,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
enum ReadExpectation {
    Exact(String),
    NonEmpty,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct PortArgs {
    port: u16,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct ConnFileArgs {
    port: u16,
    path: String,
    data: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct SendFileArgs {
    port: u16,
    size: u32,
    path: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct MultiArgs {
    port: u16,
    count: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct ExecArgs {
    port: u16,
    path: String,
    data: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct AxisServerArgs {
    path: String,
    data: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct ServerOut {
    port: u16,
    detail: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct DeleteArgs {
    path: String,
}

const LISTEN_WRITE: HandlerToken<ListenWriteArgs, DetailOut> =
    HandlerToken::new("file_tcp.listen_write");
const LISTEN_READ: HandlerToken<ListenReadArgs, DetailOut> =
    HandlerToken::new("file_tcp.listen_read");
const CONN_ECHO: HandlerToken<PortArgs, DetailOut> = HandlerToken::new("file_tcp.conn_echo");
const CONN_READ_AFTER: HandlerToken<PortArgs, DetailOut> =
    HandlerToken::new("file_tcp.conn_read_after");
const CONN_WRITE: HandlerToken<ConnFileArgs, DetailOut> = HandlerToken::new("file_tcp.conn_write");
const CONN_READBACK: HandlerToken<ConnFileArgs, DetailOut> =
    HandlerToken::new("file_tcp.conn_readback");
const SENDFILE_IN_PROCESS: HandlerToken<SendFileArgs, DetailOut> =
    HandlerToken::new("file_tcp.sendfile_in_process");
const START_ECHO_SERVER: HandlerToken<PortArgs, ServerOut> =
    HandlerToken::new("file_tcp.start_echo_server");
const SENDFILE_CLIENT: HandlerToken<SendFileArgs, DetailOut> =
    HandlerToken::new("file_tcp.sendfile_client");
const MULTI_X5: HandlerToken<MultiArgs, DetailOut> = HandlerToken::new("file_tcp.multi_x5");
const MULTI_INTERLEAVE_X5: HandlerToken<MultiArgs, DetailOut> =
    HandlerToken::new("file_tcp.multi_interleave_x5");
const EXEC_CAT_DURING_TCP: HandlerToken<ExecArgs, DetailOut> =
    HandlerToken::new("file_tcp.exec_cat_during_tcp");
const ECHO_AFTER_EXEC: HandlerToken<ExecArgs, DetailOut> =
    HandlerToken::new("file_tcp.echo_after_exec");
const AXIS_SERVER: HandlerToken<AxisServerArgs, ServerOut> =
    HandlerToken::new("file_tcp.axis_server");
const DELETE_FILE: HandlerToken<DeleteArgs, DetailOut> = HandlerToken::new("file_tcp.delete_file");

pub(crate) fn register_file_tcp(reg: &mut Registry<'_>) {
    register_handler!(LISTEN_WRITE, handle_listen_write);
    register_handler!(LISTEN_READ, handle_listen_read);
    register_handler!(CONN_ECHO, handle_conn_echo);
    register_handler!(CONN_READ_AFTER, handle_conn_read_after);
    register_handler!(CONN_WRITE, handle_conn_write);
    register_handler!(CONN_READBACK, handle_conn_readback);
    register_handler!(SENDFILE_IN_PROCESS, handle_sendfile_in_process);
    register_handler!(START_ECHO_SERVER, handle_start_echo_server);
    register_handler!(SENDFILE_CLIENT, handle_sendfile_client);
    register_handler!(MULTI_X5, handle_multi_x5);
    register_handler!(MULTI_INTERLEAVE_X5, handle_multi_interleave_x5);
    register_handler!(EXEC_CAT_DURING_TCP, handle_exec_cat_during_tcp);
    register_handler!(ECHO_AFTER_EXEC, handle_echo_after_exec);
    register_handler!(AXIS_SERVER, handle_axis_server);
    register_handler!(DELETE_FILE, handle_delete_file);

    register_listen_file_tests(reg);
    register_conn_file_tests(reg);
    register_interleave_tests(reg);
    register_multi_cycle_tests(reg);
    register_exec_during_tcp_tests(reg);
    register_axis_file_tcp_tests(reg);
}

fn register_listen_file_tests(reg: &mut Registry<'_>) {
    for &agent in &[AgentName::Dpg1, AgentName::Dpg2] {
        let port = if agent == AgentName::Dpg1 {
            18100
        } else {
            18101
        };
        let agent_label = agent.to_string();
        let id = format!("FT.listen_write.{agent}");
        reg.test("stress", "file_tcp", id)
            .timeout(180)
            .build(move |cx| {
                let handle = cx.require(agent);
                let agent_label = agent_label.clone();
                Box::new(move |run| {
                    Box::pin(async move {
                        outcome(
                            run.send_named_typed(
                                &handle,
                                &LISTEN_WRITE,
                                ListenWriteArgs {
                                    port,
                                    path: TEST_FILE.into(),
                                    data: TEST_DATA.into(),
                                },
                            )
                            .await,
                            &agent_label,
                        )
                    })
                })
            });

        let agent_label = agent.to_string();
        let id = format!("FT.listen_read.{agent}");
        reg.test("stress", "file_tcp", id)
            .timeout(180)
            .build(move |cx| {
                let handle = cx.require(agent);
                let agent_label = agent_label.clone();
                Box::new(move |run| {
                    Box::pin(async move {
                        outcome(
                            run.send_named_typed(
                                &handle,
                                &LISTEN_READ,
                                ListenReadArgs {
                                    port,
                                    path: TEST_FILE.into(),
                                    prewrite: Some(TEST_DATA.into()),
                                    expected: ReadExpectation::Exact(TEST_DATA.into()),
                                },
                            )
                            .await,
                            &agent_label,
                        )
                    })
                })
            });

        let agent_label = agent.to_string();
        let id = format!("FT.listen_read_etc.{agent}");
        reg.test("stress", "file_tcp", id)
            .timeout(180)
            .build(move |cx| {
                let handle = cx.require(agent);
                let agent_label = agent_label.clone();
                Box::new(move |run| {
                    Box::pin(async move {
                        outcome(
                            run.send_named_typed(
                                &handle,
                                &LISTEN_READ,
                                ListenReadArgs {
                                    port,
                                    path: "/etc/hostname".into(),
                                    prewrite: None,
                                    expected: ReadExpectation::NonEmpty,
                                },
                            )
                            .await,
                            &agent_label,
                        )
                    })
                })
            });
    }
}

fn register_conn_file_tests(reg: &mut Registry<'_>) {
    let port = 18110u16;
    reg.test("stress", "file_tcp", "FT.conn_echo")
        .timeout(180)
        .build(move |cx| {
            let handle = cx.require(AgentName::Dpg1);
            Box::new(move |run| {
                Box::pin(async move {
                    outcome(
                        run.send_named_typed(&handle, &CONN_ECHO, PortArgs { port })
                            .await,
                        "A",
                    )
                })
            })
        });

    reg.test("stress", "file_tcp", "FT.conn_read_after")
        .timeout(180)
        .build(move |cx| {
            let handle = cx.require(AgentName::Dpg1);
            Box::new(move |run| {
                Box::pin(async move {
                    outcome(
                        run.send_named_typed(&handle, &CONN_READ_AFTER, PortArgs { port })
                            .await,
                        "A",
                    )
                })
            })
        });

    reg.test("stress", "file_tcp", "FT.conn_write")
        .timeout(180)
        .build(move |cx| {
            let handle = cx.require(AgentName::Dpg1);
            Box::new(move |run| {
                Box::pin(async move {
                    outcome(
                        run.send_named_typed(
                            &handle,
                            &CONN_WRITE,
                            ConnFileArgs {
                                port,
                                path: "/tmp/ft_conn.txt".into(),
                                data: "during_conn".into(),
                            },
                        )
                        .await,
                        "A",
                    )
                })
            })
        });

    reg.test("stress", "file_tcp", "FT.conn_readback")
        .timeout(180)
        .build(move |cx| {
            let handle = cx.require(AgentName::Dpg1);
            Box::new(move |run| {
                Box::pin(async move {
                    outcome(
                        run.send_named_typed(
                            &handle,
                            &CONN_READBACK,
                            ConnFileArgs {
                                port,
                                path: "/tmp/ft_conn.txt".into(),
                                data: "during_conn".into(),
                            },
                        )
                        .await,
                        "A",
                    )
                })
            })
        });
}

fn register_interleave_tests(reg: &mut Registry<'_>) {
    for &(id, size, path) in &[
        ("FT.interleave_self_small", 64u32, "/tmp/ft_interleave.txt"),
        ("FT.interleave_self_4k", 4096u32, "/etc/hostname"),
        ("FT.interleave_self_32k", 32768u32, "/tmp/ft_interleave.txt"),
    ] {
        reg.test("stress", "file_tcp", id)
            .timeout(180)
            .build(move |cx| {
                let handle = cx.require(AgentName::Dpg1);
                Box::new(move |run| {
                    Box::pin(async move {
                        outcome(
                            run.send_named_typed(
                                &handle,
                                &SENDFILE_IN_PROCESS,
                                SendFileArgs {
                                    port: 18120,
                                    size,
                                    path: path.into(),
                                },
                            )
                            .await,
                            "A",
                        )
                    })
                })
            });
    }

    for &(id, size, path) in &[
        ("FT.interleave_cross_small", 64u32, "/tmp/ft_interleave.txt"),
        ("FT.interleave_cross_4k", 4096u32, "/etc/hostname"),
    ] {
        reg.test("stress", "file_tcp", id)
            .timeout(180)
            .build(move |cx| {
                let server = cx.require(AgentName::Dpg2);
                let client = cx.require(AgentName::Dpg1);
                Box::new(move |run| {
                    Box::pin(async move {
                        run_sendfile_case(run, &server, &client, 18121, size, path, "A").await
                    })
                })
            });
    }
}

fn register_multi_cycle_tests(reg: &mut Registry<'_>) {
    let port = 18130u16;
    reg.test("stress", "file_tcp", "FT.multi_x5")
        .timeout(180)
        .build(move |cx| {
            let handle = cx.require(AgentName::Dpg1);
            Box::new(move |run| {
                Box::pin(async move {
                    outcome(
                        run.send_named_typed(&handle, &MULTI_X5, MultiArgs { port, count: 5 })
                            .await,
                        "A",
                    )
                })
            })
        });

    reg.test("stress", "file_tcp", "FT.multi_interleave_x5")
        .timeout(180)
        .build(move |cx| {
            let handle = cx.require(AgentName::Dpg1);
            Box::new(move |run| {
                Box::pin(async move {
                    outcome(
                        run.send_named_typed(
                            &handle,
                            &MULTI_INTERLEAVE_X5,
                            MultiArgs { port, count: 5 },
                        )
                        .await,
                        "A",
                    )
                })
            })
        });
}

fn register_exec_during_tcp_tests(reg: &mut Registry<'_>) {
    let port = 18140u16;
    reg.test("stress", "file_tcp", "FT.exec_cat_during_tcp")
        .timeout(180)
        .build(move |cx| {
            let handle = cx.require(AgentName::Dpg1);
            Box::new(move |run| {
                Box::pin(async move {
                    outcome(
                        run.send_named_typed(
                            &handle,
                            &EXEC_CAT_DURING_TCP,
                            ExecArgs {
                                port,
                                path: "/tmp/ft_exec.txt".into(),
                                data: "exec_test_content".into(),
                            },
                        )
                        .await,
                        "A",
                    )
                })
            })
        });

    reg.test("stress", "file_tcp", "FT.echo_after_exec")
        .timeout(180)
        .build(move |cx| {
            let handle = cx.require(AgentName::Dpg1);
            Box::new(move |run| {
                Box::pin(async move {
                    outcome(
                        run.send_named_typed(
                            &handle,
                            &ECHO_AFTER_EXEC,
                            ExecArgs {
                                port,
                                path: "/tmp/ft_exec.txt".into(),
                                data: "exec_test_content".into(),
                            },
                        )
                        .await,
                        "A",
                    )
                })
            })
        });
}

#[derive(Clone, Copy)]
struct FtAxisCase {
    name: &'static str,
    server: AgentName,
    client: AgentName,
}

const FT_AXIS_CASES: &[FtAxisCase] = &[
    FtAxisCase {
        name: "parent_child",
        server: AgentName::Dpg1Dpg1,
        client: AgentName::Dpg1,
    },
    FtAxisCase {
        name: "child_parent",
        server: AgentName::Dpg1,
        client: AgentName::Dpg1Dpg1,
    },
    FtAxisCase {
        name: "depth2",
        server: AgentName::Dpg1Dng,
        client: AgentName::Dpg1DngDpg,
    },
];

fn register_axis_file_tcp_tests(reg: &mut Registry<'_>) {
    for case in FT_AXIS_CASES {
        let id = format!("FT.axis.{}", case.name);
        let server_label = case.server.to_string();
        let client_label = case.client.to_string();
        reg.test("stress", "file_tcp", id)
            .timeout(180)
            .build(move |cx| {
                let server = cx.require(case.server);
                let client = cx.require(case.client);
                Box::new(move |run| {
                    let server_label = server_label.clone();
                    let client_label = client_label.clone();
                    Box::pin(async move {
                        run_axis_file_tcp_case(
                            run,
                            &server,
                            &client,
                            &server_label,
                            &client_label,
                            case.name,
                        )
                        .await
                    })
                })
            });
    }
}

async fn run_sendfile_case(
    run: &mut RunContext<'_>,
    server: &AgentHandle,
    client: &AgentHandle,
    port: u16,
    size: u32,
    path: &str,
    label: &str,
) -> super::TestOutcome {
    if let Err(e) = run
        .send_named_typed(server, &START_ECHO_SERVER, PortArgs { port })
        .await
    {
        return super::TestOutcome::new(label, false, format!("listen failed: {e}"));
    }
    outcome(
        run.send_named_typed(
            client,
            &SENDFILE_CLIENT,
            SendFileArgs {
                port,
                size,
                path: path.into(),
            },
        )
        .await,
        label,
    )
}

async fn run_axis_file_tcp_case(
    run: &mut RunContext<'_>,
    server: &AgentHandle,
    client: &AgentHandle,
    server_label: &str,
    client_label: &str,
    axis: &str,
) -> super::TestOutcome {
    let agent = format!("{server_label}<-{client_label}");
    let path = format!("/root/litebox_ft_axis_{axis}.txt");
    let data = format!("ft_axis_payload_{axis}");
    let server_out = match run
        .send_named_typed(
            &server,
            &AXIS_SERVER,
            AxisServerArgs {
                path: path.clone(),
                data: data.clone(),
            },
        )
        .await
    {
        Ok(out) => out,
        Err(e) => return super::TestOutcome::new(&agent, false, format!("server failed: {e}")),
    };
    let resp = run
        .send_named_typed(
            &client,
            &SENDFILE_CLIENT,
            SendFileArgs {
                port: server_out.port,
                size: 128,
                path: path.clone(),
            },
        )
        .await;
    let _ = run
        .send_named_typed(&server, &DELETE_FILE, DeleteArgs { path })
        .await;
    let expected = format!("tcp_ok=128,file_len={}", data.len());
    match resp {
        Ok(out) if out.detail == expected => super::TestOutcome::new(&agent, true, out.detail),
        Ok(out) => super::TestOutcome::new(
            &agent,
            false,
            format!("expected={expected} got={}", out.detail),
        ),
        Err(e) => super::TestOutcome::new(&agent, false, e),
    }
}

async fn handle_listen_write(
    args: ListenWriteArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<DetailOut, HandlerError> {
    let listener = TcpSocket::new_tcp_listen(args.port)?;
    std::fs::write(&args.path, args.data.as_bytes())?;
    let port = listener.local_port()?;
    Ok(DetailOut {
        detail: format!("listening={port} wrote={}", args.path),
    })
}

async fn handle_listen_read(
    args: ListenReadArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<DetailOut, HandlerError> {
    let listener = TcpSocket::new_tcp_listen(args.port)?;
    if let Some(data) = args.prewrite {
        std::fs::write(&args.path, data.as_bytes())?;
    }
    let data = std::fs::read_to_string(&args.path)?;
    match &args.expected {
        ReadExpectation::Exact(expected) if &data != expected => {
            return Err(HandlerError(format!("expected {expected:?}, got {data:?}")));
        }
        ReadExpectation::NonEmpty if data.is_empty() => {
            return Err(HandlerError("read empty file".into()));
        }
        _ => {}
    }
    let port = listener.local_port()?;
    Ok(DetailOut {
        detail: format!("listening={port} read_len={}", data.len()),
    })
}

async fn handle_conn_echo(
    args: PortArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<DetailOut, HandlerError> {
    let accepted = run_in_process_echo(args.port, 1, || {
        let echo = connect_echo(args.port, "conn_test")?;
        if echo == "conn_test" {
            Ok("echo=conn_test".to_string())
        } else {
            Err(HandlerError(format!("echo mismatch: {echo:?}")))
        }
    })?;
    Ok(DetailOut {
        detail: format!("accepted={accepted}"),
    })
}

async fn handle_conn_read_after(
    args: PortArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<DetailOut, HandlerError> {
    let detail = run_in_process_echo(args.port, 1, || {
        let _ = connect_echo(args.port, "conn_test")?;
        let data = std::fs::read_to_string("/etc/hostname")?;
        if data.is_empty() {
            Err(HandlerError("hostname empty".into()))
        } else {
            Ok(format!("read_len={}", data.len()))
        }
    })?;
    Ok(DetailOut {
        detail: format!("{detail} file read after conn"),
    })
}

async fn handle_conn_write(
    args: ConnFileArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<DetailOut, HandlerError> {
    let detail = run_in_process_echo(args.port, 1, || {
        let _ = connect_echo(args.port, "conn_test")?;
        std::fs::write(&args.path, args.data.as_bytes())?;
        Ok(format!("wrote={}", args.path))
    })?;
    Ok(DetailOut { detail })
}

async fn handle_conn_readback(
    args: ConnFileArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<DetailOut, HandlerError> {
    let detail = run_in_process_echo(args.port, 1, || {
        let _ = connect_echo(args.port, "conn_test")?;
        std::fs::write(&args.path, args.data.as_bytes())?;
        let readback = std::fs::read_to_string(&args.path)?;
        if readback == args.data {
            Ok(format!("readback={readback}"))
        } else {
            Err(HandlerError(format!("readback mismatch: {readback:?}")))
        }
    })?;
    Ok(DetailOut { detail })
}

async fn handle_sendfile_in_process(
    args: SendFileArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<DetailOut, HandlerError> {
    ensure_interleave_file(&args.path)?;
    let detail = run_in_process_echo(args.port, 1, || {
        sendfile_client(args.port, args.size, &args.path)
    })?;
    Ok(DetailOut { detail })
}

async fn handle_start_echo_server(
    args: PortArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<ServerOut, HandlerError> {
    let (port, _server) = spawn_echo_server(args.port, 1)?;
    Ok(ServerOut {
        port,
        detail: format!("port={port}"),
    })
}

async fn handle_sendfile_client(
    args: SendFileArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<DetailOut, HandlerError> {
    ensure_interleave_file(&args.path)?;
    let detail = sendfile_client(args.port, args.size, &args.path)?;
    Ok(DetailOut { detail })
}

async fn handle_multi_x5(
    args: MultiArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<DetailOut, HandlerError> {
    let count = args.count;
    let detail = run_in_process_echo(args.port, count, || {
        for i in 0..count {
            let payload = format!("cycle_{i}");
            let echo = connect_echo(args.port, &payload)?;
            if echo != payload {
                return Err(HandlerError(format!("cycle {i} echo mismatch: {echo:?}")));
            }
            let path = format!("/tmp/ft_multi_{i}.txt");
            let data = format!("cycle_data_{i}");
            std::fs::write(&path, data.as_bytes())?;
            let readback = std::fs::read_to_string(&path)?;
            if readback != data {
                return Err(HandlerError(format!("cycle {i} readback mismatch")));
            }
        }
        Ok(format!("{count} file+TCP cycles"))
    })?;
    Ok(DetailOut { detail })
}

async fn handle_multi_interleave_x5(
    args: MultiArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<DetailOut, HandlerError> {
    let count = args.count;
    let detail = run_in_process_echo(args.port, count, || {
        for i in 0..count {
            let path = format!("/tmp/ft_multi_{i}.txt");
            std::fs::write(&path, format!("cycle_data_{i}").as_bytes())?;
            let detail = sendfile_client(args.port, 256, &path)?;
            if !detail.contains("tcp_ok=256") {
                return Err(HandlerError(format!("cycle {i} sendfile failed: {detail}")));
            }
        }
        Ok(format!("{count} interleaved file+TCP cycles"))
    })?;
    Ok(DetailOut { detail })
}

async fn handle_exec_cat_during_tcp(
    args: ExecArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<DetailOut, HandlerError> {
    let detail = run_in_process_echo(args.port, 1, || {
        std::fs::write(&args.path, args.data.as_bytes())?;
        let output = std::process::Command::new("cat").arg(&args.path).output()?;
        if !output.status.success() {
            return Err(HandlerError(format!("cat exit={:?}", output.status.code())));
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.trim() != args.data {
            return Err(HandlerError(format!("cat output mismatch: {stdout:?}")));
        }
        let _ = connect_echo(args.port, "exec_tcp")?;
        Ok("exec cat during tcp".to_string())
    })?;
    Ok(DetailOut { detail })
}

async fn handle_echo_after_exec(
    args: ExecArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<DetailOut, HandlerError> {
    let detail = run_in_process_echo(args.port, 1, || {
        std::fs::write(&args.path, args.data.as_bytes())?;
        let output = std::process::Command::new("cat").arg(&args.path).output()?;
        if !output.status.success() {
            return Err(HandlerError(format!("cat exit={:?}", output.status.code())));
        }
        let echo = connect_echo(args.port, "post_exec")?;
        if echo == "post_exec" {
            Ok("post_exec echo ok".to_string())
        } else {
            Err(HandlerError(format!("echo mismatch: {echo:?}")))
        }
    })?;
    Ok(DetailOut { detail })
}

async fn handle_axis_server(
    args: AxisServerArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<ServerOut, HandlerError> {
    std::fs::write(&args.path, args.data.as_bytes())?;
    let (port, _server) = spawn_echo_server(0, 1)?;
    Ok(ServerOut {
        port,
        detail: format!("port={port}"),
    })
}

async fn handle_delete_file(
    args: DeleteArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<DetailOut, HandlerError> {
    match std::fs::remove_file(&args.path) {
        Ok(()) => Ok(DetailOut {
            detail: format!("deleted={}", args.path),
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(DetailOut {
            detail: format!("not_found={}", args.path),
        }),
        Err(e) => Err(HandlerError::from(e)),
    }
}

fn run_in_process_echo<F>(port: u16, connections: u32, f: F) -> Result<String, HandlerError>
where
    F: FnOnce() -> Result<String, HandlerError>,
{
    let (_port, server) = spawn_echo_server(port, connections)?;
    let detail = f()?;
    let accepted = join_server(server)?;
    Ok(format!("{detail}; accepted={accepted}"))
}

fn spawn_echo_server(
    port: u16,
    connections: u32,
) -> Result<(u16, JoinHandle<Result<u32, std::io::Error>>), HandlerError> {
    let listener = TcpSocket::new_tcp_listen(port)?;
    let port = listener.local_port()?;
    let server = std::thread::spawn(move || -> Result<u32, std::io::Error> {
        let mut accepted = 0;
        for _ in 0..connections {
            let conn = listener.accept()?;
            accepted += 1;
            conn.echo_to_eof()?;
        }
        Ok(accepted)
    });
    Ok((port, server))
}

fn connect_echo(port: u16, payload: &str) -> Result<String, HandlerError> {
    let conn = TcpSocket::connect_loopback(port)?;
    conn.send_all(payload.as_bytes())?;
    conn.shutdown_write()?;
    conn.recv_to_end_string().map_err(HandlerError::from)
}

fn sendfile_client(port: u16, size: u32, path: &str) -> Result<String, HandlerError> {
    let pattern = pattern_bytes(size as usize);
    std::fs::write(SENDFILE_SOURCE, &pattern)?;
    let file_content = std::fs::read_to_string(path)?;
    let input = std::fs::File::open(SENDFILE_SOURCE)?;
    let conn = TcpSocket::connect_loopback(port)?;
    let mut offset: libc::off_t = 0;
    let mut remaining = pattern.len();
    while remaining > 0 {
        // SAFETY: both file descriptors are live; offset points to initialized storage
        // and sendfile copies at most `remaining` bytes from input to the socket.
        let sent =
            unsafe { libc::sendfile(conn.as_raw_fd(), input.as_raw_fd(), &mut offset, remaining) };
        if sent > 0 {
            remaining -= usize::try_from(sent).expect("positive sendfile length fits usize");
            continue;
        }
        if sent == 0 {
            return Err(HandlerError(format!(
                "sendfile EOF with {remaining} bytes remaining"
            )));
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EINTR) {
            return Err(HandlerError(format!("sendfile: {err}")));
        }
    }
    conn.shutdown_write()?;
    let echo = conn.recv_to_end_string()?;
    if echo.as_bytes() != pattern.as_slice() {
        return Err(HandlerError(format!(
            "echo mismatch: sent={} recv={}",
            pattern.len(),
            echo.len()
        )));
    }
    Ok(format!("tcp_ok={size},file_len={}", file_content.len()))
}

fn pattern_bytes(size: usize) -> Vec<u8> {
    (0..size).map(|i| b"ABCDEFGHIJKLMNOP"[i % 16]).collect()
}

fn ensure_interleave_file(path: &str) -> Result<(), HandlerError> {
    if path.starts_with("/tmp/") {
        std::fs::write(path, b"interleave_marker")?;
    }
    Ok(())
}

fn join_server(server: JoinHandle<Result<u32, std::io::Error>>) -> Result<u32, HandlerError> {
    server
        .join()
        .map_err(|_| HandlerError("server thread panicked".to_string()))?
        .map_err(HandlerError::from)
}

fn outcome(result: Result<DetailOut, String>, agent: &str) -> super::TestOutcome {
    match result {
        Ok(out) => super::TestOutcome::new(agent, true, out.detail),
        Err(e) => super::TestOutcome::new(agent, false, e),
    }
}
