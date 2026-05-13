// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! IPv4/IPv6 network special-case argv leaves.

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

pub fn run(sub: &str) -> i32 {
    match sub {
        "ipv6-socket" => test_ipv6_socket(),
        "ipv6-listen" => test_ipv6_listen(),
        "ipv6-getaddrinfo" => test_ipv6_getaddrinfo(),
        "ipv6-v6only" => test_ipv6_v6only(),
        "ipv4-listen" => test_ipv4_listen(),
        other => {
            eprintln!("unknown net test: {other}");
            1
        }
    }
}

/// NET5: `getaddrinfo("::1`") + bind + listen — the exact Node.js pattern.
fn test_ipv6_getaddrinfo() -> i32 {
    // Step 1: getaddrinfo for "::1"
    let mut hints: libc::addrinfo = unsafe { std::mem::zeroed() };
    hints.ai_family = libc::AF_INET6;
    hints.ai_socktype = libc::SOCK_STREAM;
    hints.ai_flags = libc::AI_NUMERICHOST;

    let mut result: *mut libc::addrinfo = std::ptr::null_mut();
    let host = std::ffi::CString::new("::1").unwrap();
    let port = std::ffi::CString::new("0").unwrap();
    let ret = unsafe {
        libc::getaddrinfo(
            host.as_ptr(),
            port.as_ptr(),
            &raw const hints,
            &raw mut result,
        )
    };
    if ret != 0 {
        let err = unsafe { std::ffi::CStr::from_ptr(libc::gai_strerror(ret)) };
        println!("NET5_GAI_FAIL:ret={ret},err={}", err.to_string_lossy());
        return 1;
    }
    if result.is_null() {
        println!("NET5_GAI_NULL");
        return 1;
    }

    let ai = unsafe { &*result };
    eprintln!(
        "[NET5] getaddrinfo: family={}, socktype={}, addrlen={}",
        ai.ai_family, ai.ai_socktype, ai.ai_addrlen
    );

    // Step 2: socket
    let fd = unsafe { libc::socket(ai.ai_family, ai.ai_socktype, ai.ai_protocol) };
    if fd < 0 {
        let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
        println!("NET5_SOCKET_FAIL:errno={e}");
        unsafe { libc::freeaddrinfo(result) };
        return 1;
    }

    // Step 3: setsockopt IPV6_V6ONLY (Node.js does this)
    let v6only: libc::c_int = 1;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_V6ONLY,
            (&raw const v6only).cast::<libc::c_void>(),
            std::mem::size_of::<libc::c_int>() as u32,
        )
    };
    eprintln!("[NET5] setsockopt IPV6_V6ONLY: ret={ret}");

    // Step 4: bind
    let ret = unsafe { libc::bind(fd, ai.ai_addr, ai.ai_addrlen) };
    if ret < 0 {
        let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
        println!("NET5_BIND_FAIL:errno={e}");
        unsafe {
            libc::close(fd);
            libc::freeaddrinfo(result);
        };
        return 1;
    }

    // Step 5: listen
    let ret = unsafe { libc::listen(fd, 128) };
    if ret < 0 {
        let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
        println!("NET5_LISTEN_FAIL:errno={e}");
        unsafe {
            libc::close(fd);
            libc::freeaddrinfo(result);
        };
        return 1;
    }

    unsafe {
        libc::close(fd);
        libc::freeaddrinfo(result);
    };
    println!("NET5_OK");
    0
}

/// NET6: `setsockopt(IPV6_V6ONLY)` — Node.js sets this before bind.
fn test_ipv6_v6only() -> i32 {
    let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
        println!("NET6_SOCKET_FAIL:errno={e}");
        return 1;
    }
    let v6only: libc::c_int = 1;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_V6ONLY,
            (&raw const v6only).cast::<libc::c_void>(),
            std::mem::size_of::<libc::c_int>() as u32,
        )
    };
    unsafe { libc::close(fd) };
    if ret == 0 {
        println!("NET6_OK");
        0
    } else {
        let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
        println!("NET6_FAIL:errno={e}");
        1
    }
}

/// NET1: `socket(AF_INET6`, `SOCK_STREAM`) — can we create an IPv6 socket?
fn test_ipv6_socket() -> i32 {
    let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_STREAM, 0) };
    if fd >= 0 {
        unsafe { libc::close(fd) };
        println!("NET1_OK:fd={fd}");
        0
    } else {
        let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
        println!("NET1_FAIL:errno={e}");
        1
    }
}

/// NET2: `bind(::1`, 0) + listen — the exact pattern VS Code extension host uses.
fn test_ipv6_listen() -> i32 {
    let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
        println!("NET2_SOCKET_FAIL:errno={e}");
        return 1;
    }

    let mut addr: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    addr.sin6_family = libc::AF_INET6 as u16;
    addr.sin6_port = 0; // kernel picks port
    addr.sin6_addr = libc::in6_addr {
        s6_addr: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], // ::1
    };

    let ret = unsafe {
        libc::bind(
            fd,
            (&raw const addr).cast::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_in6>() as u32,
        )
    };
    if ret < 0 {
        let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
        unsafe { libc::close(fd) };
        println!("NET2_BIND_FAIL:errno={e}");
        return 1;
    }

    let ret = unsafe { libc::listen(fd, 5) };
    if ret < 0 {
        let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
        unsafe { libc::close(fd) };
        println!("NET2_LISTEN_FAIL:errno={e}");
        return 1;
    }

    // Get the assigned port
    let mut bound: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_in6>() as u32;
    unsafe {
        libc::getsockname(fd, (&raw mut bound).cast::<libc::sockaddr>(), &raw mut len);
    }
    let port = u16::from_be(bound.sin6_port);
    unsafe { libc::close(fd) };
    println!("NET2_OK:port={port}");
    0
}

/// NET4: IPv4 listen+connect baseline (should already work).
fn test_ipv4_listen() -> i32 {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        println!("NET4_SOCKET_FAIL");
        return 1;
    }
    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    addr.sin_family = libc::AF_INET as u16;
    addr.sin_port = 0;
    addr.sin_addr.s_addr = u32::from_be(0x7f00_0001); // 127.0.0.1

    if unsafe {
        libc::bind(
            fd,
            (&raw const addr).cast::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_in>() as u32,
        )
    } < 0
    {
        let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
        unsafe { libc::close(fd) };
        println!("NET4_BIND_FAIL:errno={e}");
        return 1;
    }

    if unsafe { libc::listen(fd, 5) } < 0 {
        let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
        unsafe { libc::close(fd) };
        println!("NET4_LISTEN_FAIL:errno={e}");
        return 1;
    }

    let mut bound: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_in>() as u32;
    unsafe {
        libc::getsockname(fd, (&raw mut bound).cast::<libc::sockaddr>(), &raw mut len);
    }
    let port = u16::from_be(bound.sin_port);
    unsafe { libc::close(fd) };
    println!("NET4_OK:port={port}");
    0
}

#[allow(dead_code)]
pub(super) const RUN: HandlerToken<LeafArgs, LeafOut> = HandlerToken::new("special_cases.net.run");

#[allow(dead_code)]
pub(super) async fn handle_run(
    args: LeafArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<LeafOut, HandlerError> {
    let output = StdCommand::new(std::env::current_exe()?)
        .arg("net-test")
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

/// Register argv leaves used by exec-driven network tests.
pub(super) fn register() {
    crate::register_handler!(RUN, handle_run);
    crate::register_leaf_subcommand!("net-test", subcmd_net_test);
}

fn subcmd_net_test(args: &[String]) -> i32 {
    run(args.get(2).map_or("ipv6-socket", String::as_str))
}

/// Register IPv6 network tests.
pub(super) fn register_net_ipv6(reg: &mut Registry<'_>) {
    register();
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
                        .send_named_typed(
                            &a,
                            &EXEC_BIN,
                            ExecBinArgs {
                                argv: vec![target, "net-test".into(), sub],
                                timeout_ms: Some(10 * 1000),
                                stdin: None,
                                env: vec![],
                            },
                        )
                        .await;
                    let pass = matches!(
                        &resp,
                        Ok(out) if out.stdout.contains("_OK")
                    );
                    crate::coordinator::TestOutcome::new("A", pass, format!("{resp:?}"))
                }
            );
        }
    }
}
