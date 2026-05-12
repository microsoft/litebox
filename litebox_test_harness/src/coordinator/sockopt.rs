// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! SOCKOPT tests for socket option behaviors used by VS Code.
//!
//! Migrated to the handler-refactor protocol. Each scenario is one
//! `Command::Run` to a registered handler that performs the entire
//! setsockopt / getsockopt / bind / connect sequence inline in
//! straight-line Rust. The Net* legacy commands are no longer used
//! by this family (they remain in `agent.rs` for other families
//! that still rely on them; that's a batched-migration concern).

use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};

use crate::handlers::{HandlerCtx, HandlerError, HandlerToken};
use crate::register_handler;

use super::agents::AgentName;
use super::registry::Registry;

const SOCKOPT_AGENTS: &[AgentName] = &[
    AgentName::Dpg1,     // PIE-glibc
    AgentName::Dpg1Dpg1, // PIE-glibc depth-2
    AgentName::Dpg1Dng,  // non-PIE-glibc
    AgentName::Dpg1Spg,  // static-PIE-glibc (still uses ld.so for nss)
    AgentName::Dpg1Spm,  // static-PIE-musl — cli form, no ld.so
    AgentName::Dpg1Snm,  // non-PIE-static-musl
];

// ─── Outputs ────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Debug)]
struct ReuseaddrOut {
    port: u16,
    plain_second_failed: bool,
}

#[derive(Serialize, Deserialize, Debug)]
struct ReuseportOut {
    port: u16,
    accept_counts: Vec<u64>,
}

#[derive(Serialize, Deserialize, Debug)]
struct KeepaliveOut {
    set_ok: bool,
    get_value: bool,
}

// ─── Tokens ─────────────────────────────────────────────────────────

const REUSEADDR: HandlerToken<(), ReuseaddrOut> =
    HandlerToken::new("sockopt.reuseaddr_double_listen");
const REUSEPORT: HandlerToken<(), ReuseportOut> =
    HandlerToken::new("sockopt.reuseport_two_listeners");
const KEEPALIVE: HandlerToken<(), KeepaliveOut> = HandlerToken::new("sockopt.keepalive_roundtrip");

// ─── Handlers ───────────────────────────────────────────────────────

async fn handle_reuseaddr_double_listen(
    _args: (),
    _ctx: &mut HandlerCtx<'_>,
) -> Result<ReuseaddrOut, HandlerError> {
    // First listen on port 0 to acquire one.
    let listener1 = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener1.local_addr()?.port();

    // Second listen on the same port WITHOUT SO_REUSEADDR — must fail.
    let plain_second = TcpListener::bind(format!("127.0.0.1:{port}")).await;
    let plain_second_failed = plain_second.is_err();
    if !plain_second_failed {
        return Err(HandlerError(format!(
            "second listen on active port {port} succeeded without SO_REUSEADDR"
        )));
    }
    drop(listener1);

    // Now listen with SO_REUSEADDR.
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let socket = TcpSocket::new_v4()?;
    socket.set_reuseaddr(true)?;
    socket.bind(addr)?;
    let listener2 = socket.listen(8)?;
    drop(listener2);

    // Re-listen with SO_REUSEADDR on the same port — must succeed.
    let socket = TcpSocket::new_v4()?;
    socket.set_reuseaddr(true)?;
    socket.bind(addr)?;
    let _listener3 = socket.listen(8)?;

    Ok(ReuseaddrOut {
        port,
        plain_second_failed,
    })
}

async fn handle_reuseport_two_listeners(
    _args: (),
    _ctx: &mut HandlerCtx<'_>,
) -> Result<ReuseportOut, HandlerError> {
    // Bind two listeners with SO_REUSEPORT on the same port. Each gets
    // its own accept loop that increments its counter.
    let socket1 = TcpSocket::new_v4()?;
    socket1.set_reuseport(true)?;
    socket1.bind("127.0.0.1:0".parse().unwrap())?;
    let port = socket1.local_addr()?.port();
    let listener1 = socket1.listen(64)?;

    let socket2 = TcpSocket::new_v4()?;
    socket2.set_reuseport(true)?;
    socket2.bind(format!("127.0.0.1:{port}").parse().unwrap())?;
    let listener2 = socket2.listen(64)?;

    let count1 = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let count2 = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let t1 = tokio::spawn(echo_accept_loop(listener1, count1.clone()));
    let t2 = tokio::spawn(echo_accept_loop(listener2, count2.clone()));

    // Fire 8 connections; let the kernel distribute them across the
    // two SO_REUSEPORT listeners.
    for i in 0..8 {
        let payload = format!("sockopt_reuseport_{i}");
        let mut sock = TcpStream::connect(format!("127.0.0.1:{port}")).await?;
        sock.write_all(payload.as_bytes()).await?;
        sock.shutdown().await?;
        let mut echo = String::new();
        sock.read_to_string(&mut echo).await?;
        if echo != payload {
            return Err(HandlerError(format!(
                "connect {i}: echo mismatch want={payload:?} got={echo:?}"
            )));
        }
    }

    // Give the accept loops a moment to update counters, then stop.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    t1.abort();
    t2.abort();
    let c1 = count1.load(std::sync::atomic::Ordering::Relaxed);
    let c2 = count2.load(std::sync::atomic::Ordering::Relaxed);
    let accept_counts = vec![c1, c2];
    if accept_counts.contains(&0) {
        return Err(HandlerError(format!(
            "reuseport distribution failed: counts={accept_counts:?}"
        )));
    }
    Ok(ReuseportOut {
        port,
        accept_counts,
    })
}

async fn echo_accept_loop(listener: TcpListener, counter: Arc<std::sync::atomic::AtomicU64>) {
    loop {
        let Ok((mut sock, _peer)) = listener.accept().await else {
            return;
        };
        counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut buf = Vec::new();
        if sock.read_to_end(&mut buf).await.is_ok() {
            let _ = sock.write_all(&buf).await;
            let _ = sock.shutdown().await;
        }
    }
}

async fn handle_keepalive_roundtrip(
    _args: (),
    _ctx: &mut HandlerCtx<'_>,
) -> Result<KeepaliveOut, HandlerError> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let server = tokio::spawn(async move {
        let _ = listener.accept().await;
    });
    let sock = TcpStream::connect(format!("127.0.0.1:{port}")).await?;

    // setsockopt(SO_KEEPALIVE, 1) on the connected socket.
    let raw_fd = sock.as_raw_fd();
    let on: libc::c_int = 1;
    // SAFETY: raw_fd is a live socket; on is a valid c_int.
    let set_rc = unsafe {
        libc::setsockopt(
            raw_fd,
            libc::SOL_SOCKET,
            libc::SO_KEEPALIVE,
            std::ptr::from_ref(&on).cast::<libc::c_void>(),
            u32::try_from(std::mem::size_of::<libc::c_int>()).expect("c_int size fits in u32"),
        )
    };
    let set_ok = set_rc == 0;
    if !set_ok {
        return Err(HandlerError(format!(
            "setsockopt(SO_KEEPALIVE): {}",
            std::io::Error::last_os_error()
        )));
    }

    // getsockopt(SO_KEEPALIVE).
    let mut value: libc::c_int = 0;
    let mut len: libc::socklen_t =
        u32::try_from(std::mem::size_of::<libc::c_int>()).expect("c_int size fits in u32");
    // SAFETY: raw_fd is live; value + len are valid writable storage.
    let get_rc = unsafe {
        libc::getsockopt(
            raw_fd,
            libc::SOL_SOCKET,
            libc::SO_KEEPALIVE,
            std::ptr::from_mut(&mut value).cast::<libc::c_void>(),
            std::ptr::from_mut(&mut len),
        )
    };
    if get_rc != 0 {
        return Err(HandlerError(format!(
            "getsockopt(SO_KEEPALIVE): {}",
            std::io::Error::last_os_error()
        )));
    }
    let get_value = value != 0;

    drop(sock);
    server.abort();

    Ok(KeepaliveOut { set_ok, get_value })
}

// ─── Registration ──────────────────────────────────────────────────

pub(crate) fn register_sockopt_tests(reg: &mut Registry<'_>) {
    register_handler!(REUSEADDR, handle_reuseaddr_double_listen);
    register_handler!(REUSEPORT, handle_reuseport_two_listeners);
    register_handler!(KEEPALIVE, handle_keepalive_roundtrip);

    for &agent in SOCKOPT_AGENTS {
        reg.single_agent_handler_test(
            "vscode_gap",
            "sockopt",
            format!("SOCKOPT.reuseaddr_double_listen.{agent}"),
            agent,
            &REUSEADDR,
            |out| {
                Ok(format!(
                    "port={} plain_second_failed={}",
                    out.port, out.plain_second_failed
                ))
            },
        );
        reg.single_agent_handler_test(
            "vscode_gap",
            "sockopt",
            format!("SOCKOPT.reuseport_two_listeners.{agent}"),
            agent,
            &REUSEPORT,
            |out| {
                Ok(format!(
                    "port={} accept_counts={:?}",
                    out.port, out.accept_counts
                ))
            },
        );
        reg.single_agent_handler_test(
            "vscode_gap",
            "sockopt",
            format!("SOCKOPT.keepalive_roundtrip.{agent}"),
            agent,
            &KEEPALIVE,
            |out| {
                if out.set_ok && out.get_value {
                    Ok("keepalive set + get round-tripped".into())
                } else {
                    Err(format!("set_ok={} get_value={}", out.set_ok, out.get_value))
                }
            },
        );
    }
}
