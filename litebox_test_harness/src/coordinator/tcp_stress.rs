// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! TCP stress tests — exhaustive matrix tests for TCP connection reliability,
//! concurrency, large data transfer, and cross-worker races.
//!
//! Categories:
//! - TC: concurrent connections
//! - TD: large data transfer integrity
//! - TRR: rapid reconnect stress
//! - TW: cross-worker concurrent TCP

// TODO(#15): convert legacy wildcard enum dispatch in this file to explicit arms.
#![allow(clippy::wildcard_enum_match_arm)]

use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::handlers::{HandlerCtx, HandlerError, HandlerToken};
use crate::protocol::{Command, Response};
use crate::register_handler;

use super::agents::{AgentHandle, AgentName, EphemeralHandle, SpawnKind};
use super::registry::Registry;
use super::run_context::RunContext;

// ═══════════════════════════════════════════════════════════════════
// TC: TCP Concurrency — multiple parallel connections
// ═══════════════════════════════════════════════════════════════════

struct TcCase {
    name: &'static str,
    listener: AgentName,
    connector: AgentName,
    count: u32,
    delay_ms: u32,
}

const TC_CASES: &[TcCase] = &[
    TcCase {
        name: "in_process",
        listener: AgentName::Dpg1,
        connector: AgentName::Dpg1,
        count: 2,
        delay_ms: 0,
    },
    TcCase {
        name: "in_process",
        listener: AgentName::Dpg1,
        connector: AgentName::Dpg1,
        count: 5,
        delay_ms: 0,
    },
    TcCase {
        name: "in_process",
        listener: AgentName::Dpg1,
        connector: AgentName::Dpg1,
        count: 10,
        delay_ms: 0,
    },
    TcCase {
        name: "sibling",
        listener: AgentName::Dpg2,
        connector: AgentName::Dpg1,
        count: 2,
        delay_ms: 0,
    },
    TcCase {
        name: "sibling",
        listener: AgentName::Dpg2,
        connector: AgentName::Dpg1,
        count: 5,
        delay_ms: 0,
    },
    TcCase {
        name: "sibling",
        listener: AgentName::Dpg2,
        connector: AgentName::Dpg1,
        count: 10,
        delay_ms: 0,
    },
    TcCase {
        name: "depth2",
        listener: AgentName::Dpg1Dpg2,
        connector: AgentName::Dpg1Dpg1,
        count: 2,
        delay_ms: 0,
    },
    TcCase {
        name: "depth2",
        listener: AgentName::Dpg1Dpg2,
        connector: AgentName::Dpg1Dpg1,
        count: 5,
        delay_ms: 0,
    },
    TcCase {
        name: "sibling_delayed",
        listener: AgentName::Dpg2,
        connector: AgentName::Dpg1,
        count: 5,
        delay_ms: 10,
    },
    TcCase {
        name: "depth2_delayed",
        listener: AgentName::Dpg1Dpg2,
        connector: AgentName::Dpg1Dpg1,
        count: 5,
        delay_ms: 10,
    },
];

// ═══════════════════════════════════════════════════════════════════
// TD: TCP Data Size — large transfer integrity
// ═══════════════════════════════════════════════════════════════════

struct TdCase {
    name: &'static str,
    listener: AgentName,
    connector: AgentName,
    size: u32,
}

const TD_CASES: &[TdCase] = &[
    TdCase {
        name: "in_process",
        listener: AgentName::Dpg1,
        connector: AgentName::Dpg1,
        size: 1024,
    },
    TdCase {
        name: "sibling",
        listener: AgentName::Dpg2,
        connector: AgentName::Dpg1,
        size: 1024,
    },
    TdCase {
        name: "cross_subtree",
        listener: AgentName::Dpg1Dpg1Dpg1,
        connector: AgentName::Dpg2,
        size: 1024,
    },
    TdCase {
        name: "in_process",
        listener: AgentName::Dpg1,
        connector: AgentName::Dpg1,
        size: 65_536,
    },
    TdCase {
        name: "sibling",
        listener: AgentName::Dpg2,
        connector: AgentName::Dpg1,
        size: 65_536,
    },
    TdCase {
        name: "cross_subtree",
        listener: AgentName::Dpg1Dpg1Dpg1,
        connector: AgentName::Dpg2,
        size: 65_536,
    },
    TdCase {
        name: "in_process",
        listener: AgentName::Dpg1,
        connector: AgentName::Dpg1,
        size: 262_144,
    },
    TdCase {
        name: "sibling",
        listener: AgentName::Dpg2,
        connector: AgentName::Dpg1,
        size: 262_144,
    },
];

// ═══════════════════════════════════════════════════════════════════
// TRR: TCP Reconnect Stress — rapid sequential connections
// ═══════════════════════════════════════════════════════════════════

struct TrrCase {
    name: &'static str,
    listener: AgentName,
    connector: AgentName,
    count: u32,
}

const TRR_CASES: &[TrrCase] = &[
    TrrCase {
        name: "in_process",
        listener: AgentName::Dpg1,
        connector: AgentName::Dpg1,
        count: 5,
    },
    TrrCase {
        name: "in_process",
        listener: AgentName::Dpg1,
        connector: AgentName::Dpg1,
        count: 20,
    },
    TrrCase {
        name: "sibling",
        listener: AgentName::Dpg2,
        connector: AgentName::Dpg1,
        count: 5,
    },
    TrrCase {
        name: "sibling",
        listener: AgentName::Dpg2,
        connector: AgentName::Dpg1,
        count: 20,
    },
    TrrCase {
        name: "parent_child",
        listener: AgentName::Dpg1Dpg1,
        connector: AgentName::Dpg1,
        count: 5,
    },
    TrrCase {
        name: "child_parent",
        listener: AgentName::Dpg1,
        connector: AgentName::Dpg1Dpg1,
        count: 5,
    },
    TrrCase {
        name: "depth2",
        listener: AgentName::Dpg1Dpg1Dpg1,
        connector: AgentName::Dpg1Dpg1Dpg2,
        count: 5,
    },
];

// ═══════════════════════════════════════════════════════════════════
// TW: TCP Cross-Worker Concurrency (extends XW5/XW6)
// ═══════════════════════════════════════════════════════════════════

const TW_COUNTS: &[u32] = &[1, 3, 5];

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
struct StartListenerArgs {
    port: u16,
    expected_connections: u32,
}

#[derive(Serialize, Deserialize, Debug)]
struct StartListenerOut {
    port: u16,
    expected_connections: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct ConnectManyArgs {
    port: u16,
    data: String,
    count: u32,
    delay_ms: u32,
}

#[derive(Serialize, Deserialize, Debug)]
struct ConnectManyOut {
    success: u32,
    count: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
struct SendRecvArgs {
    port: u16,
    size: u32,
}

#[derive(Serialize, Deserialize, Debug)]
struct SendRecvOut {
    verified: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct ReconnectStressArgs {
    port: u16,
    count: u32,
    data: String,
}

const START_ECHO_LISTENER: HandlerToken<StartListenerArgs, StartListenerOut> =
    HandlerToken::new("tcp_stress.start_echo_listener");
const CONNECT_MANY: HandlerToken<ConnectManyArgs, ConnectManyOut> =
    HandlerToken::new("tcp_stress.connect_many");
const SEND_RECV: HandlerToken<SendRecvArgs, SendRecvOut> =
    HandlerToken::new("tcp_stress.send_recv");
const RECONNECT_STRESS: HandlerToken<ReconnectStressArgs, ConnectManyOut> =
    HandlerToken::new("tcp_stress.reconnect_stress");

async fn handle_start_echo_listener(
    args: StartListenerArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<StartListenerOut, HandlerError> {
    let listener = bind_loopback_listener(args.port)?;
    let expected = args.expected_connections;
    std::thread::spawn(move || echo_accept_loop(listener, expected, Duration::from_secs(30)));
    Ok(StartListenerOut {
        port: args.port,
        expected_connections: expected,
    })
}

async fn handle_connect_many(
    args: ConnectManyArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<ConnectManyOut, HandlerError> {
    let mut handles = Vec::new();
    for _ in 0..args.count {
        let data = args.data.clone().into_bytes();
        handles.push(std::thread::spawn(move || {
            connect_send_read_exact(args.port, &data, data.len()).is_ok_and(|got| got == data)
        }));
        if args.delay_ms > 0 {
            std::thread::sleep(Duration::from_millis(u64::from(args.delay_ms)));
        }
    }
    let mut success = 0u32;
    for handle in handles {
        if matches!(handle.join(), Ok(true)) {
            success += 1;
        }
    }
    Ok(ConnectManyOut {
        success,
        count: args.count,
    })
}

async fn handle_send_recv(
    args: SendRecvArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<SendRecvOut, HandlerError> {
    let pattern = pattern(args.size);
    let received = connect_send_read_exact(args.port, &pattern, pattern.len())?;
    if received.len() != pattern.len() {
        return Err(HandlerError(format!(
            "size mismatch: sent={} recv={}",
            pattern.len(),
            received.len()
        )));
    }
    if received != pattern {
        let first_diff = received
            .iter()
            .zip(pattern.iter())
            .position(|(a, b)| a != b)
            .unwrap_or(0);
        return Err(HandlerError(format!(
            "data mismatch at byte {first_diff}: got {:02x} expected {:02x}",
            received[first_diff], pattern[first_diff]
        )));
    }
    Ok(SendRecvOut {
        verified: args.size,
    })
}

async fn handle_reconnect_stress(
    args: ReconnectStressArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<ConnectManyOut, HandlerError> {
    let data = args.data.into_bytes();
    let mut success = 0u32;
    for _ in 0..args.count {
        if connect_send_read_exact(args.port, &data, data.len()).is_ok_and(|got| got == data) {
            success += 1;
        }
    }
    Ok(ConnectManyOut {
        success,
        count: args.count,
    })
}

pub(crate) fn register_tcp_stress(reg: &mut Registry<'_>) {
    register_handler!(START_ECHO_LISTENER, handle_start_echo_listener);
    register_handler!(CONNECT_MANY, handle_connect_many);
    register_handler!(SEND_RECV, handle_send_recv);
    register_handler!(RECONNECT_STRESS, handle_reconnect_stress);

    register_tcp_concurrency_tests(reg);
    register_tcp_data_size_tests(reg);
    register_tcp_reconnect_stress_tests(reg);
    register_tcp_cross_worker_concurrent_tests(reg);
}

fn register_tcp_concurrency_tests(reg: &mut Registry<'_>) {
    let mut port = 20_001u16;
    for tc in TC_CASES {
        let test_id = format!("TC.{}.x{}.d{}", tc.name, tc.count, tc.delay_ms);
        let listener = tc.listener;
        let connector = tc.connector;
        let count = tc.count;
        let delay_ms = tc.delay_ms;
        let name = tc.name.to_string();
        let p = port;
        port += 1;

        reg.test("stress", "tcp_stress", test_id)
            .timeout(180)
            .build(move |cx| {
                let listener_handle = cx.require(listener);
                let connector_handle = cx.require(connector);
                let connector_label = connector.to_string();
                Box::new(move |run| {
                    Box::pin(async move {
                        match start_listener(run, &listener_handle, p, count).await {
                            Ok(_) => {}
                            Err(e) => {
                                return super::TestOutcome::new(
                                    &connector_label,
                                    false,
                                    format!("listen failed: {e}"),
                                );
                            }
                        }
                        let args = ConnectManyArgs {
                            port: p,
                            data: format!("TC_{name}"),
                            count,
                            delay_ms,
                        };
                        let result = run
                            .send_named_typed(&connector_handle, &CONNECT_MANY, args)
                            .await;
                        connect_many_outcome(&connector_label, result)
                    })
                })
            });
    }
}

fn register_tcp_data_size_tests(reg: &mut Registry<'_>) {
    let mut port = 20_100u16;
    for tc in TD_CASES {
        let size_label = if tc.size >= 262_144 {
            "256K"
        } else if tc.size >= 65_536 {
            "64K"
        } else {
            "1K"
        };
        let test_id = format!("TD.{}.{}", size_label, tc.name);
        let listener = tc.listener;
        let connector = tc.connector;
        let size = tc.size;
        let p = port;
        port += 1;

        reg.test("stress", "tcp_stress", test_id)
            .timeout(180)
            .build(move |cx| {
                let listener_handle = cx.require(listener);
                let connector_handle = cx.require(connector);
                let connector_label = connector.to_string();
                Box::new(move |run| {
                    Box::pin(async move {
                        match start_listener(run, &listener_handle, p, 1).await {
                            Ok(_) => {}
                            Err(e) => {
                                return super::TestOutcome::new(
                                    &connector_label,
                                    false,
                                    format!("listen failed: {e}"),
                                );
                            }
                        }
                        let result = run
                            .send_named_typed(
                                &connector_handle,
                                &SEND_RECV,
                                SendRecvArgs { port: p, size },
                            )
                            .await;
                        match result {
                            Ok(out) => super::TestOutcome::new(
                                &connector_label,
                                out.verified == size,
                                format!("verified={}", out.verified),
                            ),
                            Err(e) => super::TestOutcome::new(&connector_label, false, e),
                        }
                    })
                })
            });
    }
}

fn register_tcp_reconnect_stress_tests(reg: &mut Registry<'_>) {
    let mut port = 20_200u16;
    for tc in TRR_CASES {
        let test_id = format!("TRR.x{}.{}", tc.count, tc.name);
        let listener = tc.listener;
        let connector = tc.connector;
        let count = tc.count;
        let name = tc.name.to_string();
        let p = port;
        port += 1;

        reg.test("stress", "tcp_stress", test_id)
            .timeout(180)
            .build(move |cx| {
                let listener_handle = cx.require(listener);
                let connector_handle = cx.require(connector);
                let connector_label = connector.to_string();
                Box::new(move |run| {
                    Box::pin(async move {
                        match start_listener(run, &listener_handle, p, count).await {
                            Ok(_) => {}
                            Err(e) => {
                                return super::TestOutcome::new(
                                    &connector_label,
                                    false,
                                    format!("listen failed: {e}"),
                                );
                            }
                        }
                        let args = ReconnectStressArgs {
                            port: p,
                            count,
                            data: format!("TRR_{name}"),
                        };
                        let result = run
                            .send_named_typed(&connector_handle, &RECONNECT_STRESS, args)
                            .await;
                        connect_many_outcome(&connector_label, result)
                    })
                })
            });
    }
}

#[allow(clippy::too_many_lines)] // mirrors the existing TW matrix shape
fn register_tcp_cross_worker_concurrent_tests(reg: &mut Registry<'_>) {
    #[derive(Clone, Copy)]
    struct StableCase {
        name: &'static str,
        listener: AgentName,
        connector: AgentName,
    }

    const STABLE_CASES: &[StableCase] = &[
        StableCase {
            name: "sibling",
            listener: AgentName::Dpg2,
            connector: AgentName::Dpg1,
        },
        StableCase {
            name: "depth2",
            listener: AgentName::Dpg1Dng,
            connector: AgentName::Dpg1DngDpg,
        },
    ];

    let mut port = 20_400u16;
    for &count in TW_COUNTS {
        {
            let test_id = format!("TW.remote_listen.x{count}");
            let p = port;
            port += 1;

            reg.test("stress", "tcp_stress", test_id)
                .timeout(180)
                .build(move |cx| {
                    let handle = cx.require(AgentName::Dpg1);
                    let aremote =
                        cx.declare_ephemeral(AgentName::Dpg1, "ARemote", SpawnKind::NonPie);
                    Box::new(move |run| {
                        let aremote = aremote.clone();
                        Box::pin(async move {
                            let resp = run.spawn_ephemeral(&aremote).await;
                            if !super::ok_spawned_response(&resp) {
                                return super::TestOutcome::new(
                                    "A",
                                    false,
                                    "FAIL: SpawnRemote unavailable",
                                );
                            }
                            match start_ephemeral_listener(run, &aremote, p, count).await {
                                Ok(_) => {}
                                Err(e) => {
                                    return super::TestOutcome::new(
                                        "A",
                                        false,
                                        format!("listen failed: {e}"),
                                    );
                                }
                            }
                            let args = ConnectManyArgs {
                                port: p,
                                data: "TW_REMOTE".to_string(),
                                count,
                                delay_ms: 0,
                            };
                            let result = run.send_named_typed(&handle, &CONNECT_MANY, args).await;
                            connect_many_outcome("A", result)
                        })
                    })
                });
        }

        {
            let test_id = format!("TW.local_listen.x{count}");
            let p = port;
            port += 1;

            reg.test("stress", "tcp_stress", test_id)
                .timeout(180)
                .build(move |cx| {
                    let handle = cx.require(AgentName::Dpg1);
                    let aremote =
                        cx.declare_ephemeral(AgentName::Dpg1, "ARemote", SpawnKind::NonPie);
                    Box::new(move |run| {
                        let aremote = aremote.clone();
                        Box::pin(async move {
                            let resp = run.spawn_ephemeral(&aremote).await;
                            if !super::ok_spawned_response(&resp) {
                                return super::TestOutcome::new(
                                    "A",
                                    false,
                                    "FAIL: SpawnRemote unavailable",
                                );
                            }
                            match start_listener(run, &handle, p, count).await {
                                Ok(_) => {}
                                Err(e) => {
                                    return super::TestOutcome::new(
                                        "A",
                                        false,
                                        format!("listen failed: {e}"),
                                    );
                                }
                            }
                            let args = ConnectManyArgs {
                                port: p,
                                data: "TW_LOCAL".to_string(),
                                count,
                                delay_ms: 0,
                            };
                            let result = forward_typed(run, &aremote, &CONNECT_MANY, args).await;
                            connect_many_outcome("A", result)
                        })
                    })
                });
        }

        if count == 1 {
            for case in STABLE_CASES {
                let test_id = format!("TW.{}.x{count}", case.name);
                let p = port;
                port += 1;
                let listener = case.listener;
                let connector = case.connector;
                let label = format!("{connector}->{listener}");

                reg.test("stress", "tcp_stress", test_id)
                    .timeout(180)
                    .build(move |cx| {
                        let listener_handle = cx.require(listener);
                        let connector_handle = cx.require(connector);
                        let label = label.clone();
                        Box::new(move |run| {
                            let label = label.clone();
                            Box::pin(async move {
                                match start_listener(run, &listener_handle, p, count).await {
                                    Ok(_) => {}
                                    Err(e) => {
                                        return super::TestOutcome::new(
                                            &label,
                                            false,
                                            format!("listen failed: {e}"),
                                        );
                                    }
                                }
                                let args = ConnectManyArgs {
                                    port: p,
                                    data: format!("TW_{}", case.name),
                                    count,
                                    delay_ms: 0,
                                };
                                let result = run
                                    .send_named_typed(&connector_handle, &CONNECT_MANY, args)
                                    .await;
                                connect_many_outcome(&label, result)
                            })
                        })
                    });
            }
        }
    }
}

async fn start_listener(
    run: &mut RunContext<'_>,
    handle: &AgentHandle,
    port: u16,
    expected_connections: u32,
) -> Result<StartListenerOut, String> {
    run.send_named_typed(
        handle,
        &START_ECHO_LISTENER,
        StartListenerArgs {
            port,
            expected_connections,
        },
    )
    .await
}

async fn start_ephemeral_listener(
    run: &mut RunContext<'_>,
    handle: &EphemeralHandle,
    port: u16,
    expected_connections: u32,
) -> Result<StartListenerOut, String> {
    forward_typed(
        run,
        handle,
        &START_ECHO_LISTENER,
        StartListenerArgs {
            port,
            expected_connections,
        },
    )
    .await
}

async fn forward_typed<A, O>(
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
    match run
        .forward(
            handle,
            Command::Run {
                handler: token.name().to_string(),
                args,
            },
        )
        .await
    {
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

fn connect_many_outcome(label: &str, result: Result<ConnectManyOut, String>) -> super::TestOutcome {
    match result {
        Ok(out) => super::TestOutcome::new(
            label,
            out.success == out.count,
            format!("success={}/{}", out.success, out.count),
        ),
        Err(e) => super::TestOutcome::new(label, false, e),
    }
}

fn bind_loopback_listener(port: u16) -> Result<OwnedFd, std::io::Error> {
    // SAFETY: socket creates a fresh descriptor or returns -1; no pointers involved.
    let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if raw < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: raw is a newly returned descriptor uniquely owned here.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let one: libc::c_int = 1;
    // SAFETY: fd is live; one points to a valid c_int for the call duration.
    let set_rc = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            std::ptr::from_ref(&one).cast::<libc::c_void>(),
            socklen_of::<libc::c_int>(),
        )
    };
    if set_rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let addr = loopback_sockaddr(port);
    // SAFETY: addr points to a valid sockaddr_in and fd is a live TCP socket.
    let bind_rc = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            std::ptr::from_ref(&addr).cast::<libc::sockaddr>(),
            socklen_of::<libc::sockaddr_in>(),
        )
    };
    if bind_rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: fd is a bound TCP socket.
    let listen_rc = unsafe { libc::listen(fd.as_raw_fd(), 128) };
    if listen_rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(fd)
}

fn echo_accept_loop(listener: OwnedFd, expected: u32, timeout: Duration) {
    for _ in 0..expected {
        if !poll_readable(listener.as_raw_fd(), timeout).unwrap_or(false) {
            break;
        }
        // SAFETY: listener is a live listening socket; null addr pointers are allowed.
        let raw = unsafe {
            libc::accept4(
                listener.as_raw_fd(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                libc::SOCK_CLOEXEC,
            )
        };
        if raw < 0 {
            continue;
        }
        // SAFETY: raw is a newly accepted socket descriptor.
        let conn = unsafe { OwnedFd::from_raw_fd(raw) };
        let _ = echo_one(conn);
    }
    drop(listener);
}

fn echo_one(conn: OwnedFd) -> Result<(), std::io::Error> {
    set_timeouts(conn.as_raw_fd(), Duration::from_secs(10))?;
    let mut data = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        // SAFETY: buf is writable storage and conn is live.
        let n = unsafe {
            libc::read(
                conn.as_raw_fd(),
                buf.as_mut_ptr().cast::<libc::c_void>(),
                buf.len(),
            )
        };
        if n == 0 {
            break;
        }
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(err);
        }
        data.extend_from_slice(&buf[..usize::try_from(n).expect("positive read fits usize")]);
    }
    write_all_fd(conn.as_raw_fd(), &data)?;
    // SAFETY: conn is live; shutting down both halves is valid, errors ignored during close path.
    unsafe {
        libc::shutdown(conn.as_raw_fd(), libc::SHUT_RDWR);
    }
    drop(conn);
    Ok(())
}

fn connect_send_read_exact(
    port: u16,
    payload: &[u8],
    expected_len: usize,
) -> Result<Vec<u8>, std::io::Error> {
    let fd = connect_loopback(port)?;
    set_timeouts(fd.as_raw_fd(), Duration::from_secs(10))?;
    write_all_fd(fd.as_raw_fd(), payload)?;
    // SAFETY: fd is a live connected socket; SHUT_WR sends EOF to the echo side.
    unsafe {
        libc::shutdown(fd.as_raw_fd(), libc::SHUT_WR);
    }
    read_exact_fd(fd.as_raw_fd(), expected_len)
}

fn connect_loopback(port: u16) -> Result<OwnedFd, std::io::Error> {
    // SAFETY: socket creates a fresh descriptor or returns -1; no pointers involved.
    let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if raw < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: raw is a newly returned descriptor uniquely owned here.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let addr = loopback_sockaddr(port);
    // SAFETY: addr points to a valid sockaddr_in and fd is a live TCP socket.
    let rc = unsafe {
        libc::connect(
            fd.as_raw_fd(),
            std::ptr::from_ref(&addr).cast::<libc::sockaddr>(),
            socklen_of::<libc::sockaddr_in>(),
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(fd)
}

fn write_all_fd(fd: i32, mut bytes: &[u8]) -> Result<(), std::io::Error> {
    while !bytes.is_empty() {
        // SAFETY: bytes points to readable storage and fd is expected to be live.
        let n = unsafe { libc::write(fd, bytes.as_ptr().cast::<libc::c_void>(), bytes.len()) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(err);
        }
        let n = usize::try_from(n).expect("positive write fits usize");
        bytes = &bytes[n..];
    }
    Ok(())
}

fn read_exact_fd(fd: i32, expected_len: usize) -> Result<Vec<u8>, std::io::Error> {
    let mut out = Vec::with_capacity(expected_len);
    let mut buf = [0u8; 8192];
    while out.len() < expected_len {
        let want = std::cmp::min(buf.len(), expected_len - out.len());
        // SAFETY: buf[..want] is writable storage and fd is expected to be live.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast::<libc::c_void>(), want) };
        if n == 0 {
            break;
        }
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(err);
        }
        out.extend_from_slice(&buf[..usize::try_from(n).expect("positive read fits usize")]);
    }
    Ok(out)
}

fn set_timeouts(fd: i32, timeout: Duration) -> Result<(), std::io::Error> {
    let tv = libc::timeval {
        tv_sec: i64::try_from(timeout.as_secs()).unwrap_or(i64::MAX),
        tv_usec: timeout.subsec_micros().into(),
    };
    for opt in [libc::SO_RCVTIMEO, libc::SO_SNDTIMEO] {
        // SAFETY: fd is live; tv points to a valid timeval for the call duration.
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                opt,
                std::ptr::from_ref(&tv).cast::<libc::c_void>(),
                socklen_of::<libc::timeval>(),
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

fn poll_readable(fd: i32, timeout: Duration) -> Result<bool, std::io::Error> {
    let mut pollfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let timeout_ms = i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX);
    loop {
        // SAFETY: pollfd points to one initialized pollfd entry.
        let rc = unsafe { libc::poll(std::ptr::from_mut(&mut pollfd), 1, timeout_ms) };
        if rc > 0 {
            return Ok((pollfd.revents & libc::POLLIN) != 0);
        }
        if rc == 0 {
            return Ok(false);
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EINTR) {
            return Err(err);
        }
    }
}

fn loopback_sockaddr(port: u16) -> libc::sockaddr_in {
    libc::sockaddr_in {
        sin_family: libc::AF_INET.try_into().expect("AF_INET fits sa_family_t"),
        sin_port: port.to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from(Ipv4Addr::LOCALHOST).to_be(),
        },
        sin_zero: [0; 8],
    }
}

fn pattern(size: u32) -> Vec<u8> {
    (0..size as usize)
        .map(|i| b"ABCDEFGHIJKLMNOP"[i % 16])
        .collect()
}

fn socklen_of<T>() -> libc::socklen_t {
    std::mem::size_of::<T>()
        .try_into()
        .expect("socklen_t can represent type size")
}
