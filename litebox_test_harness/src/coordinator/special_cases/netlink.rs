// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! netlink special-case argv leaves.

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
        "socket" => test_socket(),
        "bind" => test_bind(),
        "getlink" => test_getlink(),
        "getaddr" => test_getaddr(),
        "sendmsg" => test_sendmsg_recvmsg(),
        "double" => test_double_request(),
        "peek-trunc" => test_peek_trunc(),
        "full" => test_full(),
        other => {
            eprintln!("unknown: {other}");
            1
        }
    }
}

fn test_socket() -> i32 {
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };
    if fd < 0 {
        println!("NETLINK_SOCKET_FAIL:{}", errno());
        return 1;
    }
    println!("NETLINK_SOCKET_OK:{fd}");
    unsafe { libc::close(fd) };
    0
}

fn test_bind() -> i32 {
    let fd = open_nl();
    if fd < 0 {
        println!("NETLINK_SOCKET_FAIL");
        return 1;
    }
    let mut sa: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_nl>() as u32;
    if unsafe { libc::getsockname(fd, (&raw mut sa).cast::<libc::sockaddr>(), &raw mut len) } < 0 {
        println!("NETLINK_GETSOCKNAME_FAIL:{}", errno());
        unsafe { libc::close(fd) };
        return 1;
    }
    unsafe { libc::close(fd) };
    println!(
        "NETLINK_BIND_OK:family={},pid={},groups={}",
        sa.nl_family, sa.nl_pid, sa.nl_groups
    );
    if sa.nl_family != libc::AF_NETLINK as u16 {
        return 1;
    }
    0
}

fn test_getlink() -> i32 {
    let fd = open_nl();
    if fd < 0 {
        println!("NETLINK_SOCKET_FAIL");
        return 1;
    }
    let mut req = [0u8; 32]; // nlmsghdr(16) + ifinfomsg(16)
    req[0..4].copy_from_slice(&32u32.to_ne_bytes());
    req[4..6].copy_from_slice(&libc::RTM_GETLINK.to_ne_bytes());
    req[6..8].copy_from_slice(&((libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16).to_ne_bytes());
    req[8..12].copy_from_slice(&1u32.to_ne_bytes());
    if unsafe { libc::send(fd, req.as_ptr().cast(), req.len(), 0) } < 0 {
        println!("NETLINK_SEND_FAIL:{}", errno());
        unsafe { libc::close(fd) };
        return 1;
    }
    let (found, done) = recv_check(fd, libc::RTM_NEWLINK);
    unsafe { libc::close(fd) };
    if found && done {
        println!("NETLINK_GETLINK_OK");
        0
    } else {
        println!("NETLINK_GETLINK_FAIL:newlink={found},done={done}");
        1
    }
}

fn test_getaddr() -> i32 {
    let fd = open_nl();
    if fd < 0 {
        println!("NETLINK_SOCKET_FAIL");
        return 1;
    }
    let mut req = [0u8; 24]; // nlmsghdr(16) + ifaddrmsg(8)
    req[0..4].copy_from_slice(&24u32.to_ne_bytes());
    req[4..6].copy_from_slice(&libc::RTM_GETADDR.to_ne_bytes());
    req[6..8].copy_from_slice(&((libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16).to_ne_bytes());
    req[8..12].copy_from_slice(&2u32.to_ne_bytes());
    if unsafe { libc::send(fd, req.as_ptr().cast(), req.len(), 0) } < 0 {
        println!("NETLINK_SEND_FAIL:{}", errno());
        unsafe { libc::close(fd) };
        return 1;
    }
    let (found, done) = recv_check(fd, libc::RTM_NEWADDR);
    unsafe { libc::close(fd) };
    if found && done {
        println!("NETLINK_GETADDR_OK");
        0
    } else {
        println!("NETLINK_GETADDR_FAIL:newaddr={found},done={done}");
        1
    }
}

fn test_full() -> i32 {
    let mut ifaddr: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&raw mut ifaddr) } != 0 {
        println!("GETIFADDRS_FAIL:{}", errno());
        return 1;
    }
    let mut count = 0;
    let mut ptr = ifaddr;
    while !ptr.is_null() {
        count += 1;
        ptr = unsafe { (*ptr).ifa_next };
    }
    unsafe { libc::freeifaddrs(ifaddr) };
    println!("GETIFADDRS_OK:{count}");
    0
}

fn open_nl() -> i32 {
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };
    if fd < 0 {
        return fd;
    }
    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as u16;
    unsafe {
        libc::bind(
            fd,
            (&raw const addr).cast::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_nl>() as u32,
        )
    };
    fd
}

/// `NL3b`: Mimics glibc's __`netlink_request` — uses sendmsg/recvmsg
/// with `sockaddr_nl`, iov, and msghdr. This is the exact path
/// `getifaddrs()` takes internally.
fn test_sendmsg_recvmsg() -> i32 {
    let fd = open_nl();
    if fd < 0 {
        println!("NETLINK_SOCKET_FAIL");
        return 1;
    }

    // Send RTM_GETLINK via sendmsg (glibc pattern)
    let mut req = [0u8; 32]; // nlmsghdr(16) + ifinfomsg(16)
    req[0..4].copy_from_slice(&32u32.to_ne_bytes());
    req[4..6].copy_from_slice(&libc::RTM_GETLINK.to_ne_bytes());
    req[6..8].copy_from_slice(&((libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16).to_ne_bytes());
    req[8..12].copy_from_slice(&1u32.to_ne_bytes());

    let mut dst_addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    dst_addr.nl_family = libc::AF_NETLINK as u16;

    let mut iov = libc::iovec {
        iov_base: req.as_mut_ptr().cast(),
        iov_len: req.len(),
    };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = (&raw mut dst_addr).cast();
    msg.msg_namelen = std::mem::size_of::<libc::sockaddr_nl>() as u32;
    msg.msg_iov = &raw mut iov;
    msg.msg_iovlen = 1;

    let sent = unsafe { libc::sendmsg(fd, &raw const msg, 0) };
    if sent < 0 {
        println!("NETLINK_SENDMSG_FAIL:{}", errno());
        unsafe { libc::close(fd) };
        return 1;
    }
    eprintln!("[sendmsg] sent {sent} bytes");

    // Recv via recvmsg (glibc pattern) — loop until NLMSG_DONE
    let mut found_newlink = false;
    let mut found_done = false;
    let mut recv_count = 0;
    let mut buf = [0u8; 8192];
    loop {
        let mut iov_recv = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        let mut src_addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        let mut rmsg: libc::msghdr = unsafe { std::mem::zeroed() };
        rmsg.msg_name = (&raw mut src_addr).cast();
        rmsg.msg_namelen = std::mem::size_of::<libc::sockaddr_nl>() as u32;
        rmsg.msg_iov = &raw mut iov_recv;
        rmsg.msg_iovlen = 1;

        let n = unsafe { libc::recvmsg(fd, &raw mut rmsg, 0) };
        recv_count += 1;
        eprintln!("[recvmsg] call #{recv_count}: returned {n}");
        if n <= 0 {
            break;
        }
        let n = n as usize;

        let mut off = 0;
        while off + 16 <= n {
            let len =
                u32::from_ne_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]) as usize;
            let mtype = u16::from_ne_bytes([buf[off + 4], buf[off + 5]]);
            eprintln!("[recvmsg] msg at off={off}: len={len} type={mtype}");
            if len < 16 || off + len > n {
                break;
            }
            if mtype == libc::RTM_NEWLINK {
                found_newlink = true;
            }
            if mtype == libc::NLMSG_DONE as u16 {
                found_done = true;
            }
            off += (len + 3) & !3;
        }
        if found_done {
            break;
        }
    }
    unsafe { libc::close(fd) };
    if found_newlink && found_done {
        println!("NETLINK_SENDMSG_RECVMSG_OK");
        0
    } else {
        println!(
            "NETLINK_SENDMSG_RECVMSG_FAIL:newlink={found_newlink},done={found_done},recvs={recv_count}"
        );
        1
    }
}

/// `NL3c`: Two sequential requests on the same socket (like getifaddrs).
/// Send `RTM_GETLINK`, read response. Then send `RTM_GETADDR`, read response.
fn test_double_request() -> i32 {
    let fd = open_nl();
    if fd < 0 {
        println!("NETLINK_SOCKET_FAIL");
        return 1;
    }

    // Request 1: RTM_GETLINK via sendto (glibc pattern)
    let mut req1 = [0u8; 32];
    req1[0..4].copy_from_slice(&32u32.to_ne_bytes());
    req1[4..6].copy_from_slice(&libc::RTM_GETLINK.to_ne_bytes());
    req1[6..8].copy_from_slice(&((libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16).to_ne_bytes());
    req1[8..12].copy_from_slice(&1u32.to_ne_bytes());

    let mut dst: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    dst.nl_family = libc::AF_NETLINK as u16;

    eprintln!("[double] sending RTM_GETLINK via sendto");
    let sent = unsafe {
        libc::sendto(
            fd,
            req1.as_ptr().cast(),
            req1.len(),
            0,
            (&raw const dst).cast::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_nl>() as u32,
        )
    };
    eprintln!("[double] sendto returned {sent}");
    if sent < 0 {
        println!("DOUBLE_SEND1_FAIL:{}", errno());
        unsafe { libc::close(fd) };
        return 1;
    }

    let (link_ok, link_done) = recv_check(fd, libc::RTM_NEWLINK);
    eprintln!("[double] getlink: ok={link_ok} done={link_done}");
    if !link_ok || !link_done {
        println!("DOUBLE_GETLINK_FAIL:ok={link_ok},done={link_done}");
        unsafe { libc::close(fd) };
        return 1;
    }

    // Request 2: RTM_GETADDR via sendto
    let mut req2 = [0u8; 24];
    req2[0..4].copy_from_slice(&24u32.to_ne_bytes());
    req2[4..6].copy_from_slice(&libc::RTM_GETADDR.to_ne_bytes());
    req2[6..8].copy_from_slice(&((libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16).to_ne_bytes());
    req2[8..12].copy_from_slice(&2u32.to_ne_bytes());

    eprintln!("[double] sending RTM_GETADDR via sendto");
    let sent = unsafe {
        libc::sendto(
            fd,
            req2.as_ptr().cast(),
            req2.len(),
            0,
            (&raw const dst).cast::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_nl>() as u32,
        )
    };
    eprintln!("[double] sendto returned {sent}");
    if sent < 0 {
        println!("DOUBLE_SEND2_FAIL:{}", errno());
        unsafe { libc::close(fd) };
        return 1;
    }

    let (addr_ok, addr_done) = recv_check(fd, libc::RTM_NEWADDR);
    eprintln!("[double] getaddr: ok={addr_ok} done={addr_done}");

    unsafe { libc::close(fd) };
    if link_ok && link_done && addr_ok && addr_done {
        println!("NETLINK_DOUBLE_OK");
        0
    } else {
        println!("NETLINK_DOUBLE_FAIL:link={link_ok}/{link_done},addr={addr_ok}/{addr_done}");
        1
    }
}

/// `NL3d`: `MSG_PEEK` + `MSG_TRUNC` pattern — mimics glibc's __`netlink_request`.
/// glibc first does `recvmsg(MSG_PEEK|MSG_TRUNC)` with `iov_len=0` to query
/// the response size, then recvmsg(0) with a properly sized buffer.
fn test_peek_trunc() -> i32 {
    let fd = open_nl();
    if fd < 0 {
        println!("NETLINK_SOCKET_FAIL");
        return 1;
    }

    // Send RTM_GETLINK request
    let mut req = [0u8; 32];
    req[0..4].copy_from_slice(&32u32.to_ne_bytes());
    req[4..6].copy_from_slice(&libc::RTM_GETLINK.to_ne_bytes());
    req[6..8].copy_from_slice(&((libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16).to_ne_bytes());
    req[8..12].copy_from_slice(&1u32.to_ne_bytes());
    if unsafe { libc::send(fd, req.as_ptr().cast(), req.len(), 0) } < 0 {
        println!("PEEK_SEND_FAIL:{}", errno());
        unsafe { libc::close(fd) };
        return 1;
    }

    // Step 1: recvmsg(MSG_PEEK | MSG_TRUNC) with zero-length iov
    let mut iov = libc::iovec {
        iov_base: std::ptr::null_mut(),
        iov_len: 0,
    };
    let mut src_addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = (&raw mut src_addr).cast();
    msg.msg_namelen = std::mem::size_of::<libc::sockaddr_nl>() as u32;
    msg.msg_iov = &raw mut iov;
    msg.msg_iovlen = 1;

    let peek_size = unsafe { libc::recvmsg(fd, &raw mut msg, libc::MSG_PEEK | libc::MSG_TRUNC) };
    eprintln!("[peek-trunc] peek returned {peek_size}");
    if peek_size <= 0 {
        println!(
            "PEEK_TRUNC_FAIL:peek_returned={peek_size},errno={}",
            errno()
        );
        unsafe { libc::close(fd) };
        return 1;
    }

    // Step 2: recvmsg(0) with properly sized buffer
    let mut buf = vec![0u8; peek_size as usize];
    let mut iov2 = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: buf.len(),
    };
    let mut msg2: libc::msghdr = unsafe { std::mem::zeroed() };
    msg2.msg_name = (&raw mut src_addr).cast();
    msg2.msg_namelen = std::mem::size_of::<libc::sockaddr_nl>() as u32;
    msg2.msg_iov = &raw mut iov2;
    msg2.msg_iovlen = 1;

    let read_size = unsafe { libc::recvmsg(fd, &raw mut msg2, 0) };
    eprintln!("[peek-trunc] read returned {read_size}");
    if read_size <= 0 {
        println!(
            "PEEK_TRUNC_FAIL:read_returned={read_size},errno={}",
            errno()
        );
        unsafe { libc::close(fd) };
        return 1;
    }

    // Verify we got NLMSG_DONE
    let mut found_done = false;
    let n = read_size as usize;
    let mut off = 0;
    while off + 16 <= n {
        let len = u32::from_ne_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]) as usize;
        let mtype = u16::from_ne_bytes([buf[off + 4], buf[off + 5]]);
        if len < 16 || off + len > n {
            break;
        }
        if mtype == libc::NLMSG_DONE as u16 {
            found_done = true;
        }
        off += (len + 3) & !3;
    }

    unsafe { libc::close(fd) };
    // Core validation: peek size matches read size (MSG_PEEK|MSG_TRUNC works).
    // NLMSG_DONE may be in a separate message batch on real kernels with
    // many interfaces, so we don't require found_done.
    if peek_size == read_size && peek_size >= 20 {
        println!("NETLINK_PEEK_TRUNC_OK:size={peek_size}");
        0
    } else {
        println!("PEEK_TRUNC_FAIL:done={found_done},peek={peek_size},read={read_size}");
        1
    }
}

fn recv_check(fd: i32, expected: u16) -> (bool, bool) {
    let mut buf = [0u8; 8192];
    let mut found = false;
    let mut done = false;
    loop {
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), 0) };
        if n <= 0 {
            eprintln!("[recv_check] recv returned {n}");
            break;
        }
        let n = n as usize;
        // Dump first 80 bytes for debugging
        let dump_len = n.min(80);
        let hex: Vec<String> = buf[..dump_len].iter().map(|b| format!("{b:02x}")).collect();
        eprintln!("[recv_check] recv {n} bytes: {}", hex.join(" "));

        let mut off = 0;
        while off + 16 <= n {
            let len =
                u32::from_ne_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]) as usize;
            let mtype = u16::from_ne_bytes([buf[off + 4], buf[off + 5]]);
            eprintln!("[recv_check] msg at off={off}: len={len} type={mtype}");
            if len < 16 || off + len > n {
                break;
            }
            if mtype == expected {
                found = true;
            }
            if mtype == libc::NLMSG_DONE as u16 {
                done = true;
            }
            off += (len + 3) & !3;
        }
        if done {
            break;
        }
    }
    (found, done)
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
}

#[allow(dead_code)]
pub(super) const RUN: HandlerToken<LeafArgs, LeafOut> =
    HandlerToken::new("special_cases.netlink.run");

#[allow(dead_code)]
pub(super) async fn handle_run(
    args: LeafArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<LeafOut, HandlerError> {
    let output = StdCommand::new(std::env::current_exe()?)
        .arg("getifaddrs-test")
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

/// Register argv leaves used by shell/exec-driven netlink tests.
pub(super) fn register() {
    crate::register_handler!(RUN, handle_run);
    crate::register_leaf_subcommand!("getifaddrs-test", subcmd_getifaddrs_test);
}

fn subcmd_getifaddrs_test(args: &[String]) -> i32 {
    run(args.get(2).map_or("full", String::as_str))
}

/// Register netlink tests. Each test is self-contained: one exec + check.
#[allow(clippy::too_many_lines)] // exhaustive registration / runner
pub(super) fn register_netlink(reg: &mut Registry<'_>) {
    register();
    super::unix_socket::register();
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
                        let args = ExecBinArgs {
                            argv: vec![target, subcmd, arg],
                            timeout_ms: (timeout > 0).then_some(timeout * 1000),
                            stdin: None,
                            env: vec![],
                        };
                        let resp = run.send_named_typed(&a, &EXEC_BIN, args).await;
                        let pass = matches!(
                            &resp,
                            Ok(out) if out.exit_code == 0 && check(out.stdout.as_str())
                        );
                        crate::coordinator::TestOutcome::new("A", pass, format!("{resp:?}"))
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
                .send_named_typed(
                    &a,
                    &EXEC_BIN,
                    ExecBinArgs {
                        argv: vec![
                            "/usr/local/bin/node".into(),
                            "-e".into(),
                            "try { const r = require('os').networkInterfaces(); console.log('NETIF_OK:' + Object.keys(r).length); } catch(e) { console.log('NETIF_ERR:' + e.code); }".into(),
                        ],
                        timeout_ms: Some(30 * 1000),
                        stdin: None,
                        env: vec![],
                    },
                )
                .await;
            let pass = matches!(
                &resp,
                Ok(out) if out.exit_code == 0
                    && out.stdout
                        .lines()
                        .find_map(|l| l.strip_prefix("NETIF_OK:"))
                        .and_then(|s| s.trim().parse::<u32>().ok())
                        .is_some_and(|n| n > 0)
            );
            crate::coordinator::TestOutcome::new("A", pass, format!("{resp:?}"))
        }
    );
}
