// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! SCM_RIGHTS fd-passing tests over Unix domain sockets.

use crate::protocol::{Command, FdRef, Response};

use super::TestOutcome;
use super::agents::{AgentHandle, AgentName};
use super::registry::Registry;
use super::run_context::RunContext;

#[derive(Clone, Copy)]
struct ScmPair {
    sender: AgentName,
    receiver: AgentName,
}

const SCM_PAIRS: &[ScmPair] = &[
    ScmPair {
        // PIE-glibc → PIE-glibc, sibling subtree (baseline).
        sender: AgentName::Dpg1,
        receiver: AgentName::Dpg2,
    },
    ScmPair {
        // PIE-glibc → PIE-glibc, depth-2 (fd routes through one
        // hop on each side — exercises the bridge-fd inheritance).
        sender: AgentName::Dpg1Dpg1,
        receiver: AgentName::Dpg2Dpg,
    },
    // Cross-binary-type pairs. The shim's fd-bridge / replacement
    // table is driven by the parent's binary type; passing fds
    // across processes with different binary types exercises code
    // paths that same-type pairs do not.
    ScmPair {
        // PIE-glibc → non-PIE-glibc: the sshd→bash class fd passing
        // (every common Unix tool inherits an fd from its launcher).
        sender: AgentName::Dpg1,
        receiver: AgentName::Dpg1Dng,
    },
    ScmPair {
        // non-PIE-glibc → PIE-glibc: the reverse direction. Useful
        // because the receiver-side bridge install path differs
        // from the sender-side.
        sender: AgentName::Dpg1Dng,
        receiver: AgentName::Dpg1,
    },
    ScmPair {
        // non-PIE → non-PIE (the bash→bash recursion in VS Code).
        sender: AgentName::Dpg1Dng,
        receiver: AgentName::Dpg1DngDng,
    },
    ScmPair {
        // non-PIE → static-PIE-musl (the bash→cli VS Code entry
        // transition). Tests fd-passing across the cli boundary.
        sender: AgentName::Dpg1Dng,
        receiver: AgentName::Dpg1DngSpm,
    },
    ScmPair {
        // static-PIE-musl → non-PIE-glibc (the cli→node VS Code
        // signature transition). The most consequential pair for
        // VS Code Server: every fd Node.js needs (sockets, pipes,
        // pty endpoints) flows through this exact transition.
        sender: AgentName::Dpg1Spm,
        receiver: AgentName::Dpg1SpmDng,
    },
    // Static-PIE-glibc and non-PIE-static-musl coverage. Added so
    // every binary type appears as both sender and receiver at
    // least once. Without these pairs the shim's fd-table install
    // path for static-PIE-glibc and non-PIE-static-musl receivers
    // is never exercised by SCM tests.
    ScmPair {
        // static-PIE-glibc as sender (cross-tree): exercises the
        // sender-side passed_fds path on a static-PIE-glibc binary.
        sender: AgentName::Dpg1Spg,
        receiver: AgentName::Dpg2,
    },
    ScmPair {
        // non-PIE-static-musl as sender (cross-tree): exercises the
        // sender-side passed_fds path on a fully static musl binary.
        sender: AgentName::Dpg1Snm,
        receiver: AgentName::Dpg2,
    },
    ScmPair {
        // PIE-glibc → static-PIE-glibc within-tree: the receiver-side
        // fd-table install path on static-PIE-glibc (which still loads
        // ld.so for nss/dlopen but has fixed-load semantics).
        sender: AgentName::Dpg1,
        receiver: AgentName::Dpg1Spg,
    },
];

struct ScmScenario {
    name: &'static str,
    run: for<'a, 'r> fn(
        &'a mut RunContext<'r>,
        &'a AgentHandle,
        &'a AgentHandle,
        &'static str,
    ) -> ScmFuture<'a>,
}

type ScmFuture<'a> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<String, String>> + 'a>>;

const SCM_SCENARIOS: &[ScmScenario] = &[
    ScmScenario {
        name: "pass_eventfd",
        run: run_pass_eventfd,
    },
    ScmScenario {
        name: "pass_tcp_socket",
        run: run_pass_tcp_socket,
    },
    ScmScenario {
        name: "pass_then_close_sender",
        run: run_pass_then_close_sender,
    },
    ScmScenario {
        name: "pass_two_fds_one_msg",
        run: run_pass_two_fds_one_msg,
    },
];

pub(crate) fn register_scm_rights_tests(reg: &mut Registry<'_>) {
    for pair in SCM_PAIRS {
        for scenario in SCM_SCENARIOS {
            let id = format!("SCM.{}.{}_to_{}", scenario.name, pair.sender, pair.receiver);
            let label = format!("{}->{}", pair.sender, pair.receiver);
            let scenario_name = scenario.name;
            let run_scenario = scenario.run;
            reg.test("vscode", "scm_rights", id)
                .timeout(60)
                .build(move |cx| {
                    let sender = cx.require(pair.sender);
                    let receiver = cx.require(pair.receiver);
                    Box::new(move |run| {
                        let label = label.clone();
                        Box::pin(async move {
                            let result = run_scenario(run, &sender, &receiver, scenario_name).await;
                            match result {
                                Ok(detail) => TestOutcome::new(&label, true, detail),
                                Err(detail) => TestOutcome::new(&label, false, detail),
                            }
                        })
                    })
                });
        }
    }
}

fn run_pass_eventfd<'a>(
    run: &'a mut RunContext<'_>,
    sender: &'a AgentHandle,
    receiver: &'a AgentHandle,
    scenario: &'static str,
) -> ScmFuture<'a> {
    Box::pin(async move {
        let (send_sock, recv_sock, path) =
            open_scm_channel(run, sender, receiver, scenario).await?;
        let source = eventfd_open(run, sender, 0, "nonblock|cloexec").await?;
        send_fds(
            run,
            sender,
            send_sock,
            vec![FdRef::Eventfd(source)],
            "eventfd",
        )
        .await?;
        let received = recv_fds(run, receiver, recv_sock, 64, "eventfd").await?;
        let received_id = expect_one_eventfd(received)?;
        expect_closed(
            run.send(receiver, Command::UnixPairClose { socket: recv_sock })
                .await,
            "receiver socket close",
        )?;
        expect_closed(
            run.send(sender, Command::UnixPairClose { socket: send_sock })
                .await,
            "sender socket close",
        )?;
        expect_sent(
            run.send(
                sender,
                Command::EventfdWrite {
                    id: source,
                    value: 7,
                },
            )
            .await,
            "write original eventfd",
        )?;
        expect_eventfd_value(
            run.send(receiver, Command::EventfdRead { id: received_id })
                .await,
            7,
            "read received eventfd",
        )?;
        cleanup_path(&path);
        Ok(format!(
            "source_eventfd={source} received_eventfd={received_id} value=7"
        ))
    })
}

fn run_pass_tcp_socket<'a>(
    run: &'a mut RunContext<'_>,
    sender: &'a AgentHandle,
    receiver: &'a AgentHandle,
    scenario: &'static str,
) -> ScmFuture<'a> {
    Box::pin(async move {
        let (send_sock, recv_sock, path) =
            open_scm_channel(run, sender, receiver, scenario).await?;
        let listen = run
            .send(
                sender,
                Command::NetListen {
                    port: 0,
                    pre_bind_options: vec![],
                },
            )
            .await;
        let port = super::expect_listening_port(&listen, 0)
            .map_err(|e| format!("tcp listen failed: {e}; resp={listen:?}"))?;
        let conn = expect_opened(
            run.send(
                sender,
                Command::NetOpen {
                    addr: format!("127.0.0.1:{port}"),
                },
            )
            .await,
            "open tcp conn",
        )?;
        send_fds(run, sender, send_sock, vec![FdRef::TcpConn(conn)], "tcp").await?;
        let received = recv_fds(run, receiver, recv_sock, 64, "tcp").await?;
        let received_conn = expect_one_tcp(received)?;
        expect_sent(
            run.send(
                receiver,
                Command::NetSend {
                    conn: received_conn,
                    data: "SCM_TCP_PAYLOAD".into(),
                },
            )
            .await,
            "send on received tcp",
        )?;
        let echo = expect_received(
            run.send(
                receiver,
                Command::NetRecv {
                    conn: received_conn,
                    n_bytes: Some("SCM_TCP_PAYLOAD".len() as u32),
                },
            )
            .await,
            "recv tcp echo",
        )?;
        if echo != "SCM_TCP_PAYLOAD" {
            return Err(format!("tcp echo mismatch: {echo:?}"));
        }
        let _ = run
            .send(
                receiver,
                Command::NetClose {
                    conn: received_conn,
                },
            )
            .await;
        let _ = run.send(sender, Command::NetClose { conn }).await;
        let _ = run.send(sender, Command::NetUnlisten { port }).await;
        let _ = run
            .send(receiver, Command::UnixPairClose { socket: recv_sock })
            .await;
        let _ = run
            .send(sender, Command::UnixPairClose { socket: send_sock })
            .await;
        cleanup_path(&path);
        Ok(format!(
            "source_conn={conn} received_conn={received_conn} echo=ok"
        ))
    })
}

fn run_pass_then_close_sender<'a>(
    run: &'a mut RunContext<'_>,
    sender: &'a AgentHandle,
    receiver: &'a AgentHandle,
    scenario: &'static str,
) -> ScmFuture<'a> {
    Box::pin(async move {
        let (send_sock, recv_sock, path) =
            open_scm_channel(run, sender, receiver, scenario).await?;
        let source = eventfd_open(run, sender, 0, "nonblock|cloexec").await?;
        send_fds(
            run,
            sender,
            send_sock,
            vec![FdRef::Eventfd(source)],
            "close_sender",
        )
        .await?;
        let received = recv_fds(run, receiver, recv_sock, 64, "close_sender").await?;
        let received_id = expect_one_eventfd(received)?;
        expect_closed(
            run.send(sender, Command::EventfdClose { id: source }).await,
            "close sender eventfd",
        )?;
        expect_sent(
            run.send(
                receiver,
                Command::EventfdWrite {
                    id: received_id,
                    value: 5,
                },
            )
            .await,
            "write received eventfd after sender close",
        )?;
        expect_eventfd_value(
            run.send(receiver, Command::EventfdRead { id: received_id })
                .await,
            5,
            "read received eventfd after sender close",
        )?;
        let _ = run
            .send(receiver, Command::UnixPairClose { socket: recv_sock })
            .await;
        let _ = run
            .send(sender, Command::UnixPairClose { socket: send_sock })
            .await;
        cleanup_path(&path);
        Ok(format!(
            "closed_source={source} received_eventfd={received_id} still_works"
        ))
    })
}

fn run_pass_two_fds_one_msg<'a>(
    run: &'a mut RunContext<'_>,
    sender: &'a AgentHandle,
    receiver: &'a AgentHandle,
    scenario: &'static str,
) -> ScmFuture<'a> {
    Box::pin(async move {
        let (send_sock, recv_sock, path) =
            open_scm_channel(run, sender, receiver, scenario).await?;
        let first = eventfd_open(run, sender, 0, "nonblock|cloexec").await?;
        let second = eventfd_open(run, sender, 0, "nonblock|cloexec").await?;
        send_fds(
            run,
            sender,
            send_sock,
            vec![FdRef::Eventfd(first), FdRef::Eventfd(second)],
            "two_eventfds",
        )
        .await?;
        let received = recv_fds(run, receiver, recv_sock, 64, "two_eventfds").await?;
        let ids = expect_eventfds(received, 2)?;
        expect_sent(
            run.send(
                sender,
                Command::EventfdWrite {
                    id: first,
                    value: 11,
                },
            )
            .await,
            "write first original eventfd",
        )?;
        expect_sent(
            run.send(
                sender,
                Command::EventfdWrite {
                    id: second,
                    value: 13,
                },
            )
            .await,
            "write second original eventfd",
        )?;
        expect_eventfd_value(
            run.send(receiver, Command::EventfdRead { id: ids[0] })
                .await,
            11,
            "read first received eventfd",
        )?;
        expect_eventfd_value(
            run.send(receiver, Command::EventfdRead { id: ids[1] })
                .await,
            13,
            "read second received eventfd",
        )?;
        let _ = run
            .send(receiver, Command::UnixPairClose { socket: recv_sock })
            .await;
        let _ = run
            .send(sender, Command::UnixPairClose { socket: send_sock })
            .await;
        cleanup_path(&path);
        Ok(format!("received_eventfds={ids:?} values=11,13"))
    })
}

async fn open_scm_channel(
    run: &mut RunContext<'_>,
    sender: &AgentHandle,
    receiver: &AgentHandle,
    scenario: &str,
) -> Result<(u64, u64, String), String> {
    let path = format!(
        "/run/litebox-scm-{}-{scenario}-{}.sock",
        std::process::id(),
        monotonic_suffix()
    );
    match run
        .send(receiver, Command::UnixPairListen { path: path.clone() })
        .await
    {
        Response::UnixListening { path: observed } if observed == path => {}
        other => return Err(format!("unix pair listen failed: {other:?}")),
    }
    let send_sock = expect_unix_endpoint(
        run.send(sender, Command::UnixPairConnect { path: path.clone() })
            .await,
        "unix pair connect",
    )?;
    let recv_sock = expect_unix_endpoint(
        run.send(receiver, Command::UnixPairAccept { path: path.clone() })
            .await,
        "unix pair accept",
    )?;
    Ok((send_sock, recv_sock, path))
}

fn monotonic_suffix() -> u64 {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

fn cleanup_path(path: &str) {
    let _ = std::fs::remove_file(path);
}

async fn eventfd_open(
    run: &mut RunContext<'_>,
    agent: &AgentHandle,
    initval: u64,
    flags: &str,
) -> Result<u64, String> {
    match run
        .send(
            agent,
            Command::EventfdOpen {
                initval,
                flags: flags.to_string(),
            },
        )
        .await
    {
        Response::EventfdHandle { id } => Ok(id),
        other => Err(format!("eventfd_open({initval}, {flags:?}) got {other:?}")),
    }
}

async fn send_fds(
    run: &mut RunContext<'_>,
    agent: &AgentHandle,
    socket: u64,
    sources: Vec<FdRef>,
    payload: &str,
) -> Result<(), String> {
    expect_sent(
        run.send(
            agent,
            Command::UnixSendFd {
                socket,
                sources,
                payload: payload.to_string(),
            },
        )
        .await,
        "unix_send_fd",
    )
}

async fn recv_fds(
    run: &mut RunContext<'_>,
    agent: &AgentHandle,
    socket: u64,
    max_payload: u32,
    expected_payload: &str,
) -> Result<Vec<FdRef>, String> {
    match run
        .send(
            agent,
            Command::UnixRecvFd {
                socket,
                max_payload,
            },
        )
        .await
    {
        Response::ReceivedFd { received, payload } if payload == expected_payload => Ok(received),
        Response::ReceivedFd { received, payload } => Err(format!(
            "received payload mismatch: expected {expected_payload:?}, got {payload:?}; fds={received:?}"
        )),
        other => Err(format!("expected ReceivedFd, got {other:?}")),
    }
}

fn expect_unix_endpoint(resp: Response, label: &str) -> Result<u64, String> {
    match resp {
        Response::UnixPairHandle { left, .. } if left != 0 => Ok(left),
        other => Err(format!("{label}: expected UnixPairHandle, got {other:?}")),
    }
}

fn expect_one_eventfd(received: Vec<FdRef>) -> Result<u64, String> {
    let ids = expect_eventfds(received, 1)?;
    Ok(ids[0])
}

fn expect_eventfds(received: Vec<FdRef>, count: usize) -> Result<Vec<u64>, String> {
    if received.len() != count {
        return Err(format!("expected {count} received fds, got {received:?}"));
    }
    received
        .into_iter()
        .map(|fd| match fd {
            FdRef::Eventfd(id) => Ok(id),
            other => Err(format!("expected received eventfd, got {other:?}")),
        })
        .collect()
}

fn expect_one_tcp(received: Vec<FdRef>) -> Result<u64, String> {
    if received.len() != 1 {
        return Err(format!("expected one received tcp fd, got {received:?}"));
    }
    match received[0] {
        FdRef::TcpConn(id) => Ok(id),
        ref other => Err(format!("expected received tcp conn, got {other:?}")),
    }
}

fn expect_opened(resp: Response, label: &str) -> Result<u64, String> {
    match resp {
        Response::Opened { conn } => Ok(conn),
        other => Err(format!("{label}: expected Opened, got {other:?}")),
    }
}

fn expect_sent(resp: Response, label: &str) -> Result<(), String> {
    match resp {
        Response::Sent | Response::Ok { data: None } => Ok(()),
        other => Err(format!("{label}: expected Sent, got {other:?}")),
    }
}

fn expect_closed(resp: Response, label: &str) -> Result<(), String> {
    match resp {
        Response::Closed => Ok(()),
        other => Err(format!("{label}: expected Closed, got {other:?}")),
    }
}

fn expect_received(resp: Response, label: &str) -> Result<String, String> {
    match resp {
        Response::Received { data } => Ok(data),
        other => Err(format!("{label}: expected Received, got {other:?}")),
    }
}

fn expect_eventfd_value(resp: Response, expected: u64, label: &str) -> Result<(), String> {
    match resp {
        Response::EventfdValue { value } if value == expected => Ok(()),
        Response::EventfdValue { value } => Err(format!(
            "{label}: expected eventfd value {expected}, got {value}"
        )),
        other => Err(format!("{label}: expected EventfdValue, got {other:?}")),
    }
}
