// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Unix-socket special-case argv leaves.

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

use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};

pub fn run(sub: &str) -> i32 {
    match sub {
        "cross-process" => test_cross_process(),
        "cross-exec" => test_cross_exec(),
        "multi-conn" => test_multi_conn(),
        "abstract" => test_abstract_socket(),
        "race" => test_socket_race(),
        "mac" => test_mac_address(),
        "socketpair-fork-write" => test_socketpair_fork_write(),
        "socketpair-fork-read" => test_socketpair_fork_read(),
        "socketpair-fork-read-bare" => test_socketpair_fork_read_bare(),
        "socketpair-exec" => test_socketpair_exec(),
        "socketpair-shutdown" => test_socketpair_shutdown(),
        "socketpair-shutdown-parent" => test_socketpair_shutdown_parent(),
        "fork-errno-touch" => test_fork_errno_touch(),
        // Helper: child side of socketpair-exec (inherits fd from parent)
        "socketpair-exec-child" => socketpair_exec_child(),
        // Nested: exec a child that itself does socketpair+fork+exec
        // Called by the test harness binary after fork+exec for US2
        "us2-server" => us2_server(),
        // BSF: buffered-SCM-fork — parent buffers an eventfd in a
        // unix socket's recv queue via sendmsg(SCM_RIGHTS), then
        // fork+execs a (possibly cross-binary-type) child that
        // recvmsg's the buffered fd and round-trips on it. Exercises
        // the commit_delayed_fork buffered-SCM path that currently
        // returns ENOSYS in litebox when the child must migrate.
        "buffered-scm-fork" => test_buffered_scm_fork(),
        "buffered-scm-fork-child" => buffered_scm_fork_child(),
        // SXF: socketpair-fork-cross — socketpair() then fork+execv
        // into a (possibly cross-binary-type) child. Parent and
        // child exchange a PING/PONG to verify both endpoints
        // survive the commit_delayed_fork bridge. Companion to
        // p1-socketpair-fork TODO.
        "socketpair-fork-cross" => test_socketpair_fork_cross(),
        "socketpair-fork-cross-child" => socketpair_fork_cross_child(),
        // PIF: pidfd-inherit-fork — parent spawns a short-lived
        // grandchild, pidfd_open's it, fork+execvs (possibly
        // cross-binary-type) child that waitid's on the inherited
        // pidfd. Companion to p1-pidfd-inherit TODO.
        "pidfd-inherit-fork" => test_pidfd_inherit_fork(),
        "seqpacket-socketpair-boundary" => test_seqpacket_socketpair_boundary(),
        "stream-selfconnect" => test_stream_selfconnect(),
        "seqpacket-msg-trunc" => test_seqpacket_msg_trunc(),
        "seqpacket-shutdown" => test_seqpacket_shutdown(),
        "seqpacket-fork-restore-inherit" => test_seqpacket_fork_restore_inherit(),
        "seqpacket-scm-pipe-pair" => test_seqpacket_scm_pipe_pair(),
        "seqpacket-scm-file" => test_seqpacket_scm_file(),
        "seqpacket-scm-msg-ctrunc" => test_seqpacket_scm_msg_ctrunc(),
        "dgram-scm-pipe-pair" => test_dgram_scm_pipe_pair(),
        "dgram-scm-file" => test_dgram_scm_file(),
        "dgram-scm-msg-ctrunc" => test_dgram_scm_msg_ctrunc(),
        "dgram-scm-fork-restore" => test_dgram_scm_fork_restore(),
        "pidfd-inherit-child" => pidfd_inherit_child(),
        other => {
            eprintln!("unknown: {other}");
            1
        }
    }
}

/// US1: Unix socket cross-process bind+listen+connect+accept.
/// Reproduces the code-server ↔ CLI pattern:
///   child = server: bind → listen → accept → read
///   parent = client: connect → write
fn test_cross_process() -> i32 {
    let sock_path = "/tmp/litebox-us1-test.sock";
    let _ = std::fs::remove_file(sock_path);

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        println!("US1_FORK_FAIL:{}", errno());
        return 1;
    }

    if pid == 0 {
        // Child = server: bind + listen + accept + read
        eprintln!("[US1-server] binding to {sock_path}");
        let listener = match UnixListener::bind(sock_path) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("[US1-server] bind failed: {e}");
                std::process::exit(1);
            }
        };
        eprintln!("[US1-server] listening, waiting for connection...");
        match listener.accept() {
            Ok((mut stream, _addr)) => {
                let mut buf = [0u8; 64];
                match stream.read(&mut buf) {
                    Ok(n) => {
                        let msg = std::str::from_utf8(&buf[..n]).unwrap_or("?");
                        eprintln!("[US1-server] received: {msg}");
                        if msg == "HELLO_FROM_CLIENT" {
                            std::process::exit(0);
                        } else {
                            eprintln!("[US1-server] unexpected message");
                            std::process::exit(2);
                        }
                    }
                    Err(e) => {
                        eprintln!("[US1-server] read failed: {e}");
                        std::process::exit(3);
                    }
                }
            }
            Err(e) => {
                eprintln!("[US1-server] accept failed: {e}");
                std::process::exit(4);
            }
        }
    }

    // Parent = client: wait a bit for server, then connect + write
    eprintln!("[US1-client] waiting for server to start (pid={pid})...");
    std::thread::sleep(std::time::Duration::from_millis(200));

    // Retry connect up to 10 times
    let mut stream = None;
    for attempt in 0..10 {
        match UnixStream::connect(sock_path) {
            Ok(s) => {
                eprintln!("[US1-client] connected on attempt {attempt}");
                stream = Some(s);
                break;
            }
            Err(e) => {
                eprintln!("[US1-client] connect attempt {attempt} failed: {e}");
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
    }

    let Some(mut stream) = stream else {
        println!("US1_CONNECT_FAIL");
        let _ = unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
        return 1;
    };

    if let Err(e) = stream.write_all(b"HELLO_FROM_CLIENT") {
        println!("US1_WRITE_FAIL:{e}");
        let _ = unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
        return 1;
    }
    drop(stream);

    // Wait for server child
    let mut status: i32 = 0;
    unsafe { libc::waitpid(pid, &raw mut status, 0) };
    let exit_code = if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        -1
    };
    eprintln!("[US1-client] server exited with code {exit_code}");

    let _ = std::fs::remove_file(sock_path);
    if exit_code == 0 {
        println!("US1_CROSS_PROCESS_OK");
        0
    } else {
        println!("US1_CROSS_PROCESS_FAIL:exit={exit_code}");
        1
    }
}

/// VS1: Socket timing race — child delays bind, parent connects immediately.
/// Reproduces the code-server startup race.
fn test_socket_race() -> i32 {
    let sock_path = "/tmp/litebox-vs1-race.sock";
    let _ = std::fs::remove_file(sock_path);

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        println!("VS1_FORK_FAIL:{}", errno());
        return 1;
    }

    if pid == 0 {
        // Child = server: DELAY then bind + listen
        eprintln!("[VS1-server] sleeping 500ms before bind...");
        std::thread::sleep(std::time::Duration::from_millis(500));
        eprintln!("[VS1-server] binding to {sock_path}");
        let listener = match UnixListener::bind(sock_path) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("[VS1-server] bind failed: {e}");
                std::process::exit(1);
            }
        };
        eprintln!("[VS1-server] waiting for connection...");
        match listener.accept() {
            Ok((mut stream, _)) => {
                let mut buf = [0u8; 64];
                match stream.read(&mut buf) {
                    Ok(n) => {
                        let msg = std::str::from_utf8(&buf[..n]).unwrap_or("?");
                        eprintln!("[VS1-server] got: {msg}");
                        std::process::exit(if msg == "RACE_OK" { 0 } else { 2 });
                    }
                    Err(_) => std::process::exit(3),
                }
            }
            Err(_) => std::process::exit(4),
        }
    }

    // Parent = client: try connecting immediately (should fail initially, then succeed)
    eprintln!("[VS1-client] connecting immediately (server hasn't bound yet)...");
    let mut connected = false;
    let start = std::time::Instant::now();
    for attempt in 0..20 {
        match UnixStream::connect(sock_path) {
            Ok(mut s) => {
                let elapsed = start.elapsed().as_millis();
                eprintln!("[VS1-client] connected after {elapsed}ms (attempt {attempt})");
                let _ = s.write_all(b"RACE_OK");
                connected = true;
                break;
            }
            Err(e) => {
                if attempt == 0 {
                    eprintln!("[VS1-client] first connect failed (expected): {e}");
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
    }

    let mut status: i32 = 0;
    unsafe { libc::waitpid(pid, &raw mut status, 0) };
    let exit_code = if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        -1
    };
    let _ = std::fs::remove_file(sock_path);

    if connected && exit_code == 0 {
        println!("VS1_RACE_OK");
        0
    } else {
        println!("VS1_RACE_FAIL:connected={connected},exit={exit_code}");
        1
    }
}

/// NL6: Check if `os.networkInterfaces()` returns a MAC address.
/// Uses getifaddrs to check for AF_PACKET/link-layer entries.
fn test_mac_address() -> i32 {
    let mut ifaddr: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&raw mut ifaddr) } != 0 {
        println!("NL6_GETIFADDRS_FAIL:{}", errno());
        return 1;
    }

    let mut has_packet = false;
    let mut has_inet = false;
    let mut iface_count = 0;
    let mut ptr = ifaddr;
    while !ptr.is_null() {
        let ifa = unsafe { &*ptr };
        let name = unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) }.to_string_lossy();
        if !ifa.ifa_addr.is_null() {
            let family = unsafe { (*ifa.ifa_addr).sa_family };
            eprintln!("[NL6] interface={name} family={family}");
            if family == libc::AF_PACKET as u16 {
                has_packet = true;
            }
            if family == libc::AF_INET as u16 {
                has_inet = true;
            }
        }
        iface_count += 1;
        ptr = ifa.ifa_next;
    }
    unsafe { libc::freeifaddrs(ifaddr) };

    println!("NL6_MAC_CHECK:count={iface_count},has_packet={has_packet},has_inet={has_inet}");
    // has_packet=true means there's a link-layer entry with MAC
    i32::from(!has_packet)
}

/// US2: Fork+exec cross-process unix socket — tests the exec migration path.
/// Parent fork+execs a server process, then connects to its socket.
/// This is the exact pattern used by VS Code CLI → code-server.
fn test_cross_exec() -> i32 {
    let sock_path = "/tmp/litebox-us2-test.sock";
    let _ = std::fs::remove_file(sock_path);

    let self_exe = std::env::current_exe().unwrap();
    let self_exe = self_exe.to_str().unwrap();

    // Spawn child via fork+exec (this triggers remote worker migration)
    let child = std::process::Command::new(self_exe)
        .args(["unix-socket-test", "us2-server", sock_path])
        .spawn();

    let Ok(mut child) = child else {
        println!("US2_SPAWN_FAIL");
        return 1;
    };

    // Wait for server to start, then try connecting
    eprintln!(
        "[US2-client] child spawned (pid={}), retrying connect...",
        child.id()
    );
    let mut stream = None;
    for attempt in 0..30 {
        match UnixStream::connect(sock_path) {
            Ok(s) => {
                eprintln!("[US2-client] connected on attempt {attempt}");
                stream = Some(s);
                break;
            }
            Err(e) => {
                if attempt % 5 == 0 {
                    eprintln!("[US2-client] attempt {attempt}: {e}");
                }
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
        }
    }

    let Some(mut stream) = stream else {
        println!("US2_CONNECT_FAIL");
        let _ = child.kill();
        return 1;
    };

    if let Err(e) = stream.write_all(b"US2_HELLO") {
        println!("US2_WRITE_FAIL:{e}");
        let _ = child.kill();
        return 1;
    }
    let mut buf = [0u8; 64];
    let n = stream.read(&mut buf).unwrap_or(0);
    let reply = std::str::from_utf8(&buf[..n]).unwrap_or("?");
    drop(stream);

    let status = child.wait().unwrap();
    let _ = std::fs::remove_file(sock_path);

    if reply == "US2_REPLY" && status.success() {
        println!("US2_CROSS_EXEC_OK");
        0
    } else {
        println!("US2_CROSS_EXEC_FAIL:reply={reply},status={status}");
        1
    }
}

/// Server half for US2 — called after fork+exec.
fn us2_server() -> i32 {
    let sock_path = std::env::args().nth(3).unwrap_or_default();
    if sock_path.is_empty() {
        eprintln!("[US2-server] no path argument");
        return 1;
    }
    let _ = std::fs::remove_file(&sock_path);
    eprintln!("[US2-server] binding to {sock_path}");
    let listener = match UnixListener::bind(&sock_path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[US2-server] bind failed: {e}");
            return 1;
        }
    };
    eprintln!("[US2-server] listening...");
    match listener.accept() {
        Ok((mut stream, _)) => {
            let mut buf = [0u8; 64];
            let n = stream.read(&mut buf).unwrap_or(0);
            let msg = std::str::from_utf8(&buf[..n]).unwrap_or("?");
            eprintln!("[US2-server] got: {msg}");
            if msg == "US2_HELLO" {
                let _ = stream.write_all(b"US2_REPLY");
                0
            } else {
                1
            }
        }
        Err(e) => {
            eprintln!("[US2-server] accept failed: {e}");
            1
        }
    }
}

/// US4: Multiple concurrent connections to the same unix socket.
fn test_multi_conn() -> i32 {
    let sock_path = "/tmp/litebox-us4-test.sock";
    let _ = std::fs::remove_file(sock_path);

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        println!("US4_FORK_FAIL:{}", errno());
        return 1;
    }

    if pid == 0 {
        // Child = server: accept 3 connections
        let listener = match UnixListener::bind(sock_path) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("[US4-server] bind: {e}");
                std::process::exit(1);
            }
        };
        let mut count = 0;
        for i in 0..3 {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let mut buf = [0u8; 64];
                    let n = stream.read(&mut buf).unwrap_or(0);
                    let msg = std::str::from_utf8(&buf[..n]).unwrap_or("?");
                    eprintln!("[US4-server] conn {i}: {msg}");
                    if msg == format!("CONN_{i}") {
                        count += 1;
                    }
                }
                Err(e) => eprintln!("[US4-server] accept {i}: {e}"),
            }
        }
        std::process::exit(if count == 3 { 0 } else { 2 });
    }

    std::thread::sleep(std::time::Duration::from_millis(200));
    let mut ok_count = 0;
    for i in 0..3 {
        let mut connected = false;
        for _ in 0..10 {
            if let Ok(mut s) = UnixStream::connect(sock_path) {
                let _ = s.write_all(format!("CONN_{i}").as_bytes());
                drop(s);
                ok_count += 1;
                connected = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        if !connected {
            eprintln!("[US4-client] conn {i} failed");
        }
    }

    let mut status: i32 = 0;
    unsafe { libc::waitpid(pid, &raw mut status, 0) };
    let exit_code = if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        -1
    };
    let _ = std::fs::remove_file(sock_path);

    if ok_count == 3 && exit_code == 0 {
        println!("US4_MULTI_OK");
        0
    } else {
        println!("US4_MULTI_FAIL:conns={ok_count},exit={exit_code}");
        1
    }
}

/// US5: Abstract unix socket cross-process.
fn test_abstract_socket() -> i32 {
    let abstract_name = b"\0litebox-us5-test";

    // Create socket manually for abstract namespace
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        println!("US5_SOCKET_FAIL:{}", errno());
        return 1;
    }

    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as u16;
    addr.sun_path[..abstract_name.len()]
        .copy_from_slice(unsafe { &*(std::ptr::from_ref::<[u8]>(abstract_name) as *const [i8]) });
    let addr_len =
        (std::mem::size_of::<libc::sa_family_t>() + abstract_name.len()) as libc::socklen_t;

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        println!("US5_FORK_FAIL:{}", errno());
        unsafe { libc::close(fd) };
        return 1;
    }

    if pid == 0 {
        // Child = server: bind + listen + accept
        if unsafe { libc::bind(fd, (&raw const addr).cast::<libc::sockaddr>(), addr_len) } < 0 {
            eprintln!("[US5-server] bind: {}", errno());
            std::process::exit(1);
        }
        if unsafe { libc::listen(fd, 5) } < 0 {
            eprintln!("[US5-server] listen: {}", errno());
            std::process::exit(2);
        }
        eprintln!("[US5-server] waiting for connection...");
        let client_fd = unsafe { libc::accept(fd, std::ptr::null_mut(), std::ptr::null_mut()) };
        if client_fd < 0 {
            eprintln!("[US5-server] accept: {}", errno());
            std::process::exit(3);
        }
        let mut buf = [0u8; 64];
        let n = unsafe { libc::read(client_fd, buf.as_mut_ptr().cast(), buf.len()) };
        unsafe {
            libc::close(client_fd);
            libc::close(fd);
        }
        let msg = std::str::from_utf8(&buf[..n.max(0) as usize]).unwrap_or("?");
        std::process::exit(if msg == "US5_HELLO" { 0 } else { 4 });
    }

    // Parent = client
    unsafe { libc::close(fd) }; // close the server socket in parent
    std::thread::sleep(std::time::Duration::from_millis(300));

    let cfd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if cfd < 0 {
        println!("US5_CLIENT_SOCKET_FAIL:{}", errno());
        let _ = unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
        return 1;
    }

    let mut connected = false;
    for attempt in 0..10 {
        if unsafe { libc::connect(cfd, (&raw const addr).cast::<libc::sockaddr>(), addr_len) } == 0
        {
            eprintln!("[US5-client] connected on attempt {attempt}");
            connected = true;
            break;
        }
        eprintln!("[US5-client] attempt {attempt}: errno={}", errno());
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    if connected {
        unsafe { libc::write(cfd, b"US5_HELLO".as_ptr().cast(), 9) };
    }
    unsafe { libc::close(cfd) };

    let mut status: i32 = 0;
    unsafe { libc::waitpid(pid, &raw mut status, 0) };
    let exit_code = if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        -1
    };

    if connected && exit_code == 0 {
        println!("US5_ABSTRACT_OK");
        0
    } else {
        println!("US5_ABSTRACT_FAIL:connected={connected},exit={exit_code}");
        1
    }
}

/// `US6a`: `socketpair(AF_UNIX)` + fork — child WRITES to inherited fd.
/// Reproduces the VS Code extension host IPC pattern (child→parent):
///   parent: `socketpair()` → `fork()` → waitpid → read from `parent_end`
///   child:  write to `child_end` → exit
/// Uses vfork-compatible sequencing: child writes + exits before parent reads.
fn test_socketpair_fork_write() -> i32 {
    let mut fds = [0i32; 2];
    let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
    if rc != 0 {
        println!("US6_SOCKETPAIR_FAIL:{}", errno());
        return 1;
    }
    let parent_fd = fds[0];
    let child_fd = fds[1];
    eprintln!("[US6a] socketpair ok: parent_fd={parent_fd}, child_fd={child_fd}");

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        println!("US6_FORK_FAIL:{}", errno());
        return 1;
    }

    if pid == 0 {
        unsafe { libc::close(parent_fd) };
        let msg = b"US6_FROM_CHILD";
        let n = unsafe { libc::write(child_fd, msg.as_ptr().cast::<libc::c_void>(), msg.len()) };
        if n != msg.len() as isize {
            eprintln!("[US6a-child] write failed: n={n} errno={}", errno());
            unsafe { libc::_exit(1) };
        }
        eprintln!("[US6a-child] wrote {n} bytes");
        unsafe { libc::close(child_fd) };
        unsafe { libc::_exit(0) };
    }

    unsafe { libc::close(child_fd) };
    let mut status = 0i32;
    unsafe { libc::waitpid(pid, &raw mut status, 0) };
    let exit_code = if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        99
    };

    if exit_code != 0 {
        println!("US6_CHILD_FAIL:exit={exit_code}");
        unsafe { libc::close(parent_fd) };
        return 1;
    }

    let mut buf = [0u8; 64];
    let n = unsafe {
        libc::read(
            parent_fd,
            buf.as_mut_ptr().cast::<libc::c_void>(),
            buf.len(),
        )
    };
    unsafe { libc::close(parent_fd) };

    if n <= 0 {
        println!("US6_READ_FAIL:n={n},errno={}", errno());
        return 1;
    }
    let msg = std::str::from_utf8(&buf[..n as usize]).unwrap_or("?");
    eprintln!("[US6a-parent] got: {msg}");

    if msg == "US6_FROM_CHILD" {
        println!("US6_SOCKETPAIR_FORK_OK");
        0
    } else {
        println!("US6_SOCKETPAIR_FORK_FAIL:msg={msg}");
        1
    }
}

/// `US6b`: `socketpair(AF_UNIX)` + fork — child READS from inherited fd.
/// Tests the reverse direction (parent→child):
///   parent: `socketpair()` → `fork()` → write to `parent_end` → waitpid
///   child:  read from `child_end` → exit(based on data)
/// Requires true concurrent fork (not vfork).
fn test_socketpair_fork_read() -> i32 {
    let mut fds = [0i32; 2];
    let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
    if rc != 0 {
        println!("US6R_SOCKETPAIR_FAIL:{}", errno());
        return 1;
    }
    let parent_fd = fds[0];
    let child_fd = fds[1];
    eprintln!("[US6b] socketpair ok: parent_fd={parent_fd}, child_fd={child_fd}");

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        println!("US6R_FORK_FAIL:{}", errno());
        return 1;
    }

    if pid == 0 {
        // Child: close parent end, read from child end, exit.
        unsafe { libc::close(parent_fd) };
        let tv = libc::timeval {
            tv_sec: 5,
            tv_usec: 0,
        };
        unsafe {
            libc::setsockopt(
                child_fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                (&raw const tv).cast::<libc::c_void>(),
                core::mem::size_of::<libc::timeval>() as libc::socklen_t,
            );
        }
        let mut buf = [0u8; 64];
        let n = unsafe { libc::read(child_fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
        if n <= 0 {
            eprintln!("[US6b-child] read failed: n={n} errno={}", errno());
            unsafe { libc::_exit(1) };
        }
        let msg = std::str::from_utf8(&buf[..n as usize]).unwrap_or("?");
        eprintln!("[US6b-child] got: {msg}");
        std::process::exit(if msg == "US6_FROM_PARENT" { 0 } else { 2 });
    }

    // Parent: close child end, write to parent end, waitpid.
    unsafe { libc::close(child_fd) };
    let msg = b"US6_FROM_PARENT";
    let n = unsafe { libc::write(parent_fd, msg.as_ptr().cast::<libc::c_void>(), msg.len()) };
    unsafe { libc::close(parent_fd) };

    if n != msg.len() as isize {
        println!("US6R_WRITE_FAIL:n={n},errno={}", errno());
        unsafe { libc::kill(pid, libc::SIGKILL) };
        return 1;
    }
    eprintln!("[US6b-parent] wrote {n} bytes");

    let mut status = 0i32;
    unsafe { libc::waitpid(pid, &raw mut status, 0) };
    let exit_code = if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        99
    };

    if exit_code == 0 {
        println!("US6R_SOCKETPAIR_FORK_READ_OK");
        0
    } else {
        println!("US6R_SOCKETPAIR_FORK_READ_FAIL:exit={exit_code}");
        1
    }
}

/// FET: bare socketpair + fork read leaf with no child-side Rust formatting after `fork()`.
fn test_socketpair_fork_read_bare() -> i32 {
    let mut fds = [0i32; 2];
    let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
    if rc != 0 {
        println!("US6R_BARE_SOCKETPAIR_FAIL:{}", errno());
        return 1;
    }

    let parent_fd = fds[0];
    let child_fd = fds[1];
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        println!("US6R_BARE_FORK_FAIL:{}", errno());
        unsafe {
            libc::close(parent_fd);
            libc::close(child_fd);
        }
        return 1;
    }

    if pid == 0 {
        unsafe {
            libc::close(parent_fd);
            let mut byte = 0u8;
            let n = libc::read(child_fd, (&raw mut byte).cast::<libc::c_void>(), 1);
            libc::_exit(if n == 1 && byte == b'X' { 0 } else { 1 });
        }
    }

    unsafe { libc::close(child_fd) };
    let byte = b"X";
    let n = unsafe { libc::write(parent_fd, byte.as_ptr().cast::<libc::c_void>(), 1) };
    unsafe { libc::close(parent_fd) };
    if n != 1 {
        println!("US6R_BARE_WRITE_FAIL:n={n},errno={}", errno());
        unsafe { libc::kill(pid, libc::SIGKILL) };
        return 1;
    }

    let mut status = 0i32;
    unsafe { libc::waitpid(pid, &raw mut status, 0) };
    if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 {
        println!("US6R_BARE_SOCKETPAIR_FORK_READ_OK");
        0
    } else {
        let exit_code = if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else {
            99
        };
        println!("US6R_BARE_SOCKETPAIR_FORK_READ_FAIL:exit={exit_code}");
        1
    }
}

/// FET: fork child touches libc errno before exec.
/// Isolates fork return restoring guest FS/TLS before any child-side libc code.
fn test_fork_errno_touch() -> i32 {
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        println!("FET_FORK_FAIL:{}", errno());
        return 1;
    }

    if pid == 0 {
        unsafe {
            let errno_ptr = libc::__errno_location();
            *errno_ptr = libc::EBADF;
            libc::_exit(if *errno_ptr == libc::EBADF { 0 } else { 2 });
        }
    }

    let mut status = 0i32;
    unsafe { libc::waitpid(pid, &raw mut status, 0) };
    if libc::WIFEXITED(status) {
        let exit_code = libc::WEXITSTATUS(status);
        if exit_code == 0 {
            println!("FET_FORK_ERRNO_TOUCH_OK");
            0
        } else {
            println!("FET_FORK_ERRNO_TOUCH_FAIL:exit={exit_code}");
            1
        }
    } else if libc::WIFSIGNALED(status) {
        println!("FET_FORK_ERRNO_TOUCH_SIGNAL:sig={}", libc::WTERMSIG(status));
        1
    } else {
        println!("FET_FORK_ERRNO_TOUCH_WAIT_FAIL:status={status}");
        1
    }
}

/// `US6c`: `socketpair(AF_UNIX)` + fork+exec — bidirectional IPC.
/// Reproduces the exact VS Code extension host pattern:
///   parent: `socketpair()` → `fork()` → exec(child, inheriting fd) → write → read
///   child (exec'd): read from inherited fd → write reply → exit
/// Uses raw fork+exec (not `posix_spawn`) to trigger litebox's delayed fork.
fn test_socketpair_exec() -> i32 {
    let mut fds = [0i32; 2];
    let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
    if rc != 0 {
        println!("US6E_SOCKETPAIR_FAIL:{}", errno());
        return 1;
    }
    let parent_fd = fds[0];
    let child_fd = fds[1];
    eprintln!("[US6c] socketpair ok: parent_fd={parent_fd}, child_fd={child_fd}");

    // Clear CLOEXEC on child_fd so it survives exec.
    unsafe { libc::fcntl(child_fd, libc::F_SETFD, 0) };

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        println!("US6E_FORK_FAIL:{}", errno());
        return 1;
    }

    if pid == 0 {
        // Child: close parent end, exec self with child fd arg.
        // Only pre-exec syscalls before execv — triggers exec-on-remote-host
        // path (not commit_delayed_fork).
        unsafe { libc::close(parent_fd) };
        let self_exe = std::env::current_exe().unwrap();
        let self_exe = self_exe.to_str().unwrap();
        let fd_str = child_fd.to_string();
        let c_exe = std::ffi::CString::new(self_exe).unwrap();
        let c_arg1 = std::ffi::CString::new("unix-socket-test").unwrap();
        let c_arg2 = std::ffi::CString::new("socketpair-exec-child").unwrap();
        let c_arg3 = std::ffi::CString::new(fd_str.as_str()).unwrap();
        let args = [
            c_exe.as_ptr(),
            c_arg1.as_ptr(),
            c_arg2.as_ptr(),
            c_arg3.as_ptr(),
            core::ptr::null(),
        ];
        unsafe { libc::execv(c_exe.as_ptr(), args.as_ptr()) };
        eprintln!("[US6c-child] execv failed: {}", errno());
        std::process::exit(127);
    }

    // Parent: close child end, write, read reply, waitpid.
    unsafe { libc::close(child_fd) };

    let msg = b"US6E_FROM_PARENT";
    let n = unsafe { libc::write(parent_fd, msg.as_ptr().cast::<libc::c_void>(), msg.len()) };
    if n != msg.len() as isize {
        println!("US6E_WRITE_FAIL:n={n},errno={}", errno());
        unsafe { libc::kill(pid, libc::SIGKILL) };
        return 1;
    }
    eprintln!("[US6c-parent] wrote {n} bytes");

    // Read reply with timeout.
    let tv = libc::timeval {
        tv_sec: 10,
        tv_usec: 0,
    };
    unsafe {
        libc::setsockopt(
            parent_fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&raw const tv).cast::<libc::c_void>(),
            core::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
    }
    let mut buf = [0u8; 64];
    let n = unsafe {
        libc::read(
            parent_fd,
            buf.as_mut_ptr().cast::<libc::c_void>(),
            buf.len(),
        )
    };
    unsafe { libc::close(parent_fd) };

    let mut status = 0i32;
    unsafe { libc::waitpid(pid, &raw mut status, 0) };
    let exit_code = if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        99
    };

    if n <= 0 {
        println!("US6E_READ_FAIL:n={n},errno={},exit={exit_code}", errno());
        return 1;
    }
    let reply = std::str::from_utf8(&buf[..n as usize]).unwrap_or("?");
    eprintln!("[US6c-parent] got reply: {reply}");

    if reply == "US6E_FROM_CHILD" && exit_code == 0 {
        println!("US6E_SOCKETPAIR_EXEC_OK");
        0
    } else {
        println!("US6E_SOCKETPAIR_EXEC_FAIL:reply={reply},exit={exit_code}");
        1
    }
}

/// `US6S`: `socketpair(AF_UNIX)` + `shutdown(SHUT_WR)` — minimal repro
/// for the wave-6 W6-C5 fix. Node.js's libuv child_process spawn calls
/// `shutdown(fd, SHUT_WR)` on a broker-backed socketpair fd to signal
/// half-close. Pre-fix, this dispatch was missing from the shim, so
/// the syscall hung — and any spawnSync() child waiting on the parent
/// (e.g., for stdout pipe drain) also stalled.
///
/// This test: parent creates a socketpair, fork+exec'd child sends
/// "PING" then `shutdown(SHUT_WR)` to signal "done sending", parent
/// reads "PING" then sees EOF (which only happens if shutdown
/// propagated correctly).
fn test_socketpair_shutdown() -> i32 {
    let mut fds = [0i32; 2];
    let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
    if rc != 0 {
        println!("US6S_SOCKETPAIR_FAIL:{}", errno());
        return 1;
    }
    let parent_fd = fds[0];
    let child_fd = fds[1];
    eprintln!("[US6S] socketpair ok: parent_fd={parent_fd}, child_fd={child_fd}");

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        println!("US6S_FORK_FAIL:{}", errno());
        return 1;
    }

    if pid == 0 {
        // Child: write PING then shutdown(SHUT_WR), exit.
        unsafe { libc::close(parent_fd) };
        let msg = b"PING";
        let n = unsafe { libc::write(child_fd, msg.as_ptr().cast::<libc::c_void>(), msg.len()) };
        if n != msg.len() as isize {
            eprintln!("[US6S-child] write failed n={n} errno={}", errno());
            unsafe { libc::_exit(1) };
        }
        let rc = unsafe { libc::shutdown(child_fd, libc::SHUT_WR) };
        if rc != 0 {
            eprintln!("[US6S-child] shutdown(SHUT_WR) failed: {}", errno());
            unsafe { libc::_exit(2) };
        }
        unsafe { libc::close(child_fd) };
        unsafe { libc::_exit(0) };
    }

    // Parent: close child end, set a recv timeout so we fail loudly
    // instead of hanging the test, read PING, expect EOF on next read.
    unsafe { libc::close(child_fd) };
    let tv = libc::timeval {
        tv_sec: 5,
        tv_usec: 0,
    };
    unsafe {
        libc::setsockopt(
            parent_fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&raw const tv).cast::<libc::c_void>(),
            core::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
    }

    let mut buf = [0u8; 64];
    let n = unsafe {
        libc::read(
            parent_fd,
            buf.as_mut_ptr().cast::<libc::c_void>(),
            buf.len(),
        )
    };
    if n != 4 {
        println!("US6S_READ1_FAIL:n={n},errno={}", errno());
        unsafe { libc::kill(pid, libc::SIGKILL) };
        unsafe { libc::close(parent_fd) };
        return 1;
    }
    let msg = std::str::from_utf8(&buf[..n as usize]).unwrap_or("?");
    if msg != "PING" {
        println!("US6S_BAD_PING:msg={msg:?}");
        unsafe { libc::kill(pid, libc::SIGKILL) };
        unsafe { libc::close(parent_fd) };
        return 1;
    }

    // Second read should return 0 (EOF) because child did shutdown(SHUT_WR).
    let n2 = unsafe {
        libc::read(
            parent_fd,
            buf.as_mut_ptr().cast::<libc::c_void>(),
            buf.len(),
        )
    };
    unsafe { libc::close(parent_fd) };
    if n2 != 0 {
        println!("US6S_NO_EOF:n2={n2},errno={}", errno());
        unsafe { libc::kill(pid, libc::SIGKILL) };
        return 1;
    }

    let mut status = 0i32;
    unsafe { libc::waitpid(pid, &raw mut status, 0) };
    let exit_code = if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        99
    };
    if exit_code != 0 {
        println!("US6S_CHILD_FAIL:exit={exit_code}");
        return 1;
    }

    println!("US6S_SOCKETPAIR_SHUTDOWN_OK");
    0
}

/// `US6SP`: parent-side `shutdown(SHUT_WR)`. Mirrors node's libuv
/// pattern more precisely: parent does the shutdown on its write end
/// after sending its message, child reads to EOF then echoes back.
fn test_socketpair_shutdown_parent() -> i32 {
    let mut fds = [0i32; 2];
    let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
    if rc != 0 {
        println!("US6SP_SOCKETPAIR_FAIL:{}", errno());
        return 1;
    }
    let parent_fd = fds[0];
    let child_fd = fds[1];

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        println!("US6SP_FORK_FAIL:{}", errno());
        return 1;
    }

    if pid == 0 {
        // Child: read until EOF, then write reply.
        unsafe { libc::close(parent_fd) };
        let mut acc = Vec::<u8>::new();
        let mut buf = [0u8; 64];
        loop {
            let n =
                unsafe { libc::read(child_fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
            if n <= 0 {
                break;
            }
            acc.extend_from_slice(&buf[..n as usize]);
        }
        let reply = b"PONG";
        let _ =
            unsafe { libc::write(child_fd, reply.as_ptr().cast::<libc::c_void>(), reply.len()) };
        unsafe { libc::close(child_fd) };
        unsafe { libc::_exit(if acc == b"PING" { 0 } else { 1 }) };
    }

    // Parent: send PING, shutdown(SHUT_WR), read reply.
    unsafe { libc::close(child_fd) };
    let msg = b"PING";
    let n = unsafe { libc::write(parent_fd, msg.as_ptr().cast::<libc::c_void>(), msg.len()) };
    if n != msg.len() as isize {
        println!("US6SP_WRITE_FAIL:n={n},errno={}", errno());
        unsafe { libc::kill(pid, libc::SIGKILL) };
        return 1;
    }
    let rc = unsafe { libc::shutdown(parent_fd, libc::SHUT_WR) };
    if rc != 0 {
        println!("US6SP_SHUTDOWN_FAIL:errno={}", errno());
        unsafe { libc::kill(pid, libc::SIGKILL) };
        return 1;
    }
    let tv = libc::timeval {
        tv_sec: 5,
        tv_usec: 0,
    };
    unsafe {
        libc::setsockopt(
            parent_fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&raw const tv).cast::<libc::c_void>(),
            core::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
    }
    let mut buf = [0u8; 64];
    let n2 = unsafe {
        libc::read(
            parent_fd,
            buf.as_mut_ptr().cast::<libc::c_void>(),
            buf.len(),
        )
    };
    unsafe { libc::close(parent_fd) };
    let mut status = 0i32;
    unsafe { libc::waitpid(pid, &raw mut status, 0) };
    let exit_code = if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        99
    };
    let reply = if n2 > 0 {
        std::str::from_utf8(&buf[..n2 as usize]).unwrap_or("?")
    } else {
        "?"
    };
    if n2 != 4 || reply != "PONG" || exit_code != 0 {
        println!("US6SP_FAIL:n2={n2},reply={reply:?},exit={exit_code}");
        return 1;
    }
    println!("US6SP_SOCKETPAIR_SHUTDOWN_PARENT_OK");
    0
}

/// Helper for `US6c`: exec'd child reads from inherited socketpair fd,
/// writes reply, exits.
fn socketpair_exec_child() -> i32 {
    let fd: i32 = std::env::args()
        .nth(3)
        .and_then(|s| s.parse().ok())
        .unwrap_or(-1);
    if fd < 0 {
        eprintln!("[US6c-child] bad fd arg");
        return 1;
    }

    let tv = libc::timeval {
        tv_sec: 5,
        tv_usec: 0,
    };
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&raw const tv).cast::<libc::c_void>(),
            core::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
    }

    let mut buf = [0u8; 64];
    let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
    if n <= 0 {
        eprintln!("[US6c-child] read failed: n={n} errno={}", errno());
        return 1;
    }
    let msg = std::str::from_utf8(&buf[..n as usize]).unwrap_or("?");
    eprintln!("[US6c-child] got: {msg}");

    let reply = b"US6E_FROM_CHILD";
    let w = unsafe { libc::write(fd, reply.as_ptr().cast::<libc::c_void>(), reply.len()) };
    unsafe { libc::close(fd) };

    if msg == "US6E_FROM_PARENT" && w == reply.len() as isize {
        0
    } else {
        2
    }
}

/// BSF parent — buffered-SCM-fork:
/// 1. socketpair(AF_UNIX, SOCK_STREAM) → (s_send, s_recv)
/// 2. eventfd(initval=0)
/// 3. sendmsg(s_send, SCM_RIGHTS=[ev], data="BSF") — message lands
///    in s_recv's recv queue, not yet drained.
/// 4. close(s_send) to ensure the child does not race writers.
/// 5. fork+execv(child_exe, "unix-socket-test",
///    "buffered-scm-fork-child", "<s_recv_fd>"). The fork(+exec) is
///    the trigger for `commit_delayed_fork` to bridge s_recv across
///    host workers when child_exe is a different binary type —
///    that bridge is the gate currently returning ENOSYS.
/// 6. waitpid; emit BSF_OK iff child exit==0.
fn test_buffered_scm_fork() -> i32 {
    let child_exe: String = std::env::args().nth(3).unwrap_or_default();
    if child_exe.is_empty() {
        println!("BSF_USAGE: unix-socket-test buffered-scm-fork <child_exe>");
        return 1;
    }
    let mut fds = [0i32; 2];
    let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
    if rc != 0 {
        println!("BSF_SOCKETPAIR_FAIL:{}", errno());
        return 1;
    }
    let s_send = fds[0];
    let s_recv = fds[1];

    let ev = unsafe { libc::eventfd(0, 0) };
    if ev < 0 {
        println!("BSF_EVENTFD_FAIL:{}", errno());
        return 1;
    }

    let payload = b"BSF";
    let mut iov = libc::iovec {
        iov_base: payload.as_ptr() as *mut libc::c_void,
        iov_len: payload.len(),
    };
    let mut cmsg_buf = [0u8; 32];
    let mut msg: libc::msghdr = unsafe { core::mem::zeroed() };
    msg.msg_iov = &raw mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr().cast::<libc::c_void>();
    msg.msg_controllen = cmsg_buf.len() as _;
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&raw const msg);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(core::mem::size_of::<i32>() as u32) as _;
        let data = libc::CMSG_DATA(cmsg).cast::<i32>();
        data.write_unaligned(ev);
        msg.msg_controllen = libc::CMSG_SPACE(core::mem::size_of::<i32>() as u32) as _;
    }
    let n = unsafe { libc::sendmsg(s_send, &raw const msg, 0) };
    if n < 0 {
        println!("BSF_SENDMSG_FAIL:{}", errno());
        return 1;
    }

    unsafe {
        libc::close(s_send);
        libc::close(ev);
    }
    unsafe { libc::fcntl(s_recv, libc::F_SETFD, 0) };

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        println!("BSF_FORK_FAIL:{}", errno());
        return 1;
    }

    if pid == 0 {
        let fd_str = s_recv.to_string();
        let c_exe = std::ffi::CString::new(child_exe.as_str()).unwrap();
        let c_a1 = std::ffi::CString::new("unix-socket-test").unwrap();
        let c_a2 = std::ffi::CString::new("buffered-scm-fork-child").unwrap();
        let c_a3 = std::ffi::CString::new(fd_str.as_str()).unwrap();
        let argv = [
            c_exe.as_ptr(),
            c_a1.as_ptr(),
            c_a2.as_ptr(),
            c_a3.as_ptr(),
            core::ptr::null(),
        ];
        unsafe { libc::execv(c_exe.as_ptr(), argv.as_ptr()) };
        eprintln!("[BSF-child] execv failed: {}", errno());
        std::process::exit(127);
    }

    unsafe { libc::close(s_recv) };
    let mut status = 0i32;
    unsafe { libc::waitpid(pid, &raw mut status, 0) };
    let exit_code = if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        99
    };
    if exit_code == 0 {
        println!("BSF_OK");
        0
    } else {
        println!("BSF_FAIL:exit={exit_code}");
        1
    }
}

/// BSF child — recvmsg the buffered SCM_RIGHTS message, then
/// eventfd_write/read on the recovered fd to verify it's wired
/// up to a real broker handle (or kernel eventfd, on native).
fn buffered_scm_fork_child() -> i32 {
    let fd: i32 = std::env::args()
        .nth(3)
        .and_then(|s| s.parse().ok())
        .unwrap_or(-1);
    if fd < 0 {
        eprintln!("[BSF-child] bad fd arg");
        return 1;
    }
    let mut buf = [0u8; 32];
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast::<libc::c_void>(),
        iov_len: buf.len(),
    };
    let mut cmsg_buf = [0u8; 64];
    let mut msg: libc::msghdr = unsafe { core::mem::zeroed() };
    msg.msg_iov = &raw mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr().cast::<libc::c_void>();
    msg.msg_controllen = cmsg_buf.len() as _;
    let n = unsafe { libc::recvmsg(fd, &raw mut msg, 0) };
    if n < 0 {
        eprintln!("[BSF-child] recvmsg failed: {}", errno());
        return 2;
    }
    let mut got_ev: i32 = -1;
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&raw const msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                let data = libc::CMSG_DATA(cmsg).cast::<i32>();
                got_ev = data.read_unaligned();
                break;
            }
            cmsg = libc::CMSG_NXTHDR(&raw const msg, cmsg);
        }
    }
    if got_ev < 0 {
        eprintln!("[BSF-child] no SCM_RIGHTS in recvmsg result");
        return 3;
    }
    let v: u64 = 0x4243_5f4f_4b21;
    let w = unsafe { libc::write(got_ev, (&raw const v).cast::<libc::c_void>(), 8) };
    if w != 8 {
        eprintln!("[BSF-child] write to ev failed: w={w} errno={}", errno());
        return 4;
    }
    let mut r: u64 = 0;
    let rn = unsafe { libc::read(got_ev, (&raw mut r).cast::<libc::c_void>(), 8) };
    unsafe {
        libc::close(got_ev);
        libc::close(fd);
    }
    if rn != 8 || r != v {
        eprintln!("[BSF-child] read mismatch: rn={rn} r={r:#x} expected={v:#x}");
        return 5;
    }
    0
}

/// SXF parent — socketpair-fork-cross:
/// socketpair → clear CLOEXEC on child end → fork+execv child_exe.
/// Parent writes PING on its end; child writes PONG back. Verifies
/// both endpoints of a socketpair survive the cross-host-runner
/// bridge in `commit_delayed_fork` when child_exe is a different
/// binary type.
fn test_socketpair_fork_cross() -> i32 {
    let child_exe: String = std::env::args().nth(3).unwrap_or_default();
    if child_exe.is_empty() {
        println!("SXF_USAGE: unix-socket-test socketpair-fork-cross <child_exe>");
        return 1;
    }
    let mut fds = [0i32; 2];
    let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
    if rc != 0 {
        println!("SXF_SOCKETPAIR_FAIL:{}", errno());
        return 1;
    }
    let parent_fd = fds[0];
    let child_fd = fds[1];
    unsafe { libc::fcntl(child_fd, libc::F_SETFD, 0) };

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        println!("SXF_FORK_FAIL:{}", errno());
        return 1;
    }
    if pid == 0 {
        unsafe { libc::close(parent_fd) };
        let fd_str = child_fd.to_string();
        let c_exe = std::ffi::CString::new(child_exe.as_str()).unwrap();
        let c_a1 = std::ffi::CString::new("unix-socket-test").unwrap();
        let c_a2 = std::ffi::CString::new("socketpair-fork-cross-child").unwrap();
        let c_a3 = std::ffi::CString::new(fd_str.as_str()).unwrap();
        let argv = [
            c_exe.as_ptr(),
            c_a1.as_ptr(),
            c_a2.as_ptr(),
            c_a3.as_ptr(),
            core::ptr::null(),
        ];
        unsafe { libc::execv(c_exe.as_ptr(), argv.as_ptr()) };
        eprintln!("[SXF-child] execv failed: {}", errno());
        std::process::exit(127);
    }
    unsafe { libc::close(child_fd) };

    let tv = libc::timeval {
        tv_sec: 10,
        tv_usec: 0,
    };
    unsafe {
        libc::setsockopt(
            parent_fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&raw const tv).cast::<libc::c_void>(),
            core::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
    }

    let ping = b"SXF_PING";
    let w = unsafe { libc::write(parent_fd, ping.as_ptr().cast::<libc::c_void>(), ping.len()) };
    if w != ping.len() as isize {
        println!("SXF_WRITE_FAIL:n={w} errno={}", errno());
        unsafe { libc::kill(pid, libc::SIGKILL) };
        return 1;
    }
    let mut buf = [0u8; 32];
    let n = unsafe {
        libc::read(
            parent_fd,
            buf.as_mut_ptr().cast::<libc::c_void>(),
            buf.len(),
        )
    };
    unsafe { libc::close(parent_fd) };
    let mut status = 0i32;
    unsafe { libc::waitpid(pid, &raw mut status, 0) };
    let exit_code = if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        99
    };
    if n <= 0 {
        println!("SXF_READ_FAIL:n={n},errno={},exit={exit_code}", errno());
        return 1;
    }
    let reply = core::str::from_utf8(&buf[..n as usize]).unwrap_or("?");
    if reply == "SXF_PONG" && exit_code == 0 {
        println!("SXF_OK");
        0
    } else {
        println!("SXF_FAIL:reply={reply},exit={exit_code}");
        1
    }
}

fn socketpair_fork_cross_child() -> i32 {
    let fd: i32 = std::env::args()
        .nth(3)
        .and_then(|s| s.parse().ok())
        .unwrap_or(-1);
    if fd < 0 {
        eprintln!("[SXF-child] bad fd arg");
        return 1;
    }
    let tv = libc::timeval {
        tv_sec: 5,
        tv_usec: 0,
    };
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&raw const tv).cast::<libc::c_void>(),
            core::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
    }
    let mut buf = [0u8; 32];
    let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
    if n <= 0 {
        eprintln!("[SXF-child] read failed: n={n} errno={}", errno());
        return 2;
    }
    let msg = core::str::from_utf8(&buf[..n as usize]).unwrap_or("?");
    if msg != "SXF_PING" {
        eprintln!("[SXF-child] unexpected msg: {msg}");
        return 3;
    }
    let pong = b"SXF_PONG";
    let w = unsafe { libc::write(fd, pong.as_ptr().cast::<libc::c_void>(), pong.len()) };
    unsafe { libc::close(fd) };
    if w == pong.len() as isize { 0 } else { 4 }
}

/// PIF parent — pidfd-inherit-fork:
/// 1. fork() a short-lived grandchild that sleeps then exits.
/// 2. pidfd_open(grandchild_pid).
/// 3. Clear CLOEXEC on the pidfd.
/// 4. fork+execv(child_exe, ..., pidfd, grandchild_pid).
/// Child poll()s + waitid()s on the inherited pidfd; reports PIF_OK
/// iff the wait observes the grandchild's exit. Validates that pidfd
/// inheritance survives a cross-host-runner exec.
fn test_pidfd_inherit_fork() -> i32 {
    let child_exe: String = std::env::args().nth(3).unwrap_or_default();
    if child_exe.is_empty() {
        println!("PIF_USAGE: unix-socket-test pidfd-inherit-fork <child_exe>");
        return 1;
    }
    // Spawn a grandchild that sleeps 2s then exits cleanly.
    let gpid = unsafe { libc::fork() };
    if gpid < 0 {
        println!("PIF_GRANDCHILD_FORK_FAIL:{}", errno());
        return 1;
    }
    if gpid == 0 {
        unsafe { libc::sleep(2) };
        std::process::exit(0);
    }

    // pidfd_open(SYS_pidfd_open=434 on x86_64).
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, gpid, 0) } as i32;
    if pidfd < 0 {
        println!("PIF_PIDFD_OPEN_FAIL:{}", errno());
        unsafe { libc::kill(gpid, libc::SIGKILL) };
        return 1;
    }
    unsafe { libc::fcntl(pidfd, libc::F_SETFD, 0) };

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        println!("PIF_FORK_FAIL:{}", errno());
        unsafe { libc::kill(gpid, libc::SIGKILL) };
        return 1;
    }
    if pid == 0 {
        let fd_str = pidfd.to_string();
        let gpid_str = gpid.to_string();
        let c_exe = std::ffi::CString::new(child_exe.as_str()).unwrap();
        let c_a1 = std::ffi::CString::new("unix-socket-test").unwrap();
        let c_a2 = std::ffi::CString::new("pidfd-inherit-child").unwrap();
        let c_a3 = std::ffi::CString::new(fd_str.as_str()).unwrap();
        let c_a4 = std::ffi::CString::new(gpid_str.as_str()).unwrap();
        let argv = [
            c_exe.as_ptr(),
            c_a1.as_ptr(),
            c_a2.as_ptr(),
            c_a3.as_ptr(),
            c_a4.as_ptr(),
            core::ptr::null(),
        ];
        unsafe { libc::execv(c_exe.as_ptr(), argv.as_ptr()) };
        eprintln!("[PIF-child] execv failed: {}", errno());
        std::process::exit(127);
    }
    unsafe { libc::close(pidfd) };

    let mut status = 0i32;
    unsafe { libc::waitpid(pid, &raw mut status, 0) };
    let child_exit = if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        99
    };
    // Reap the grandchild if the child didn't (defensive — the
    // child's waitid on the pidfd does not reap on some kernels).
    unsafe { libc::waitpid(gpid, &raw mut status, libc::WNOHANG) };

    if child_exit == 0 {
        println!("PIF_OK");
        0
    } else {
        println!("PIF_FAIL:exit={child_exit}");
        1
    }
}

fn pidfd_inherit_child() -> i32 {
    let pidfd: i32 = std::env::args()
        .nth(3)
        .and_then(|s| s.parse().ok())
        .unwrap_or(-1);
    let gpid: i32 = std::env::args()
        .nth(4)
        .and_then(|s| s.parse().ok())
        .unwrap_or(-1);
    if pidfd < 0 || gpid < 0 {
        eprintln!("[PIF-child] bad args");
        return 1;
    }
    // poll(pidfd, POLLIN, 10s) — fires when the (sibling, not
    // child) grandchild exits. We can't use waitid(P_PIDFD)
    // here: waitid requires the target to be a child of the
    // calling process, but the grandchild was forked by our
    // parent. POLLIN on pidfd works cross-process.
    let mut pfd = libc::pollfd {
        fd: pidfd,
        events: libc::POLLIN,
        revents: 0,
    };
    let rc = unsafe { libc::poll(&raw mut pfd, 1, 10_000) };
    unsafe { libc::close(pidfd) };
    if rc <= 0 {
        eprintln!("[PIF-child] poll failed: rc={rc} errno={}", errno());
        return 2;
    }
    if pfd.revents & libc::POLLIN == 0 {
        eprintln!("[PIF-child] no POLLIN: revents={}", pfd.revents);
        return 3;
    }
    // Sanity: also verify the grandchild process is gone.
    let _ = gpid;
    0
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
}

#[allow(dead_code)]
pub(super) const RUN: HandlerToken<LeafArgs, LeafOut> =
    HandlerToken::new("special_cases.unix_socket.run");

#[allow(dead_code)]
pub(super) async fn handle_run(
    args: LeafArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<LeafOut, HandlerError> {
    let output = StdCommand::new(std::env::current_exe()?)
        .arg("unix-socket-test")
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

/// Register argv leaves used by shell/exec-driven Unix-socket tests and exec children.
pub(super) fn register() {
    crate::register_handler!(RUN, handle_run);
    crate::register_leaf_subcommand!("unix-socket-test", subcmd_unix_socket_test);
}

fn subcmd_unix_socket_test(args: &[String]) -> i32 {
    run(args.get(2).map_or("cross-process", String::as_str))
}

// Register unix socket tests.
#[allow(clippy::too_many_lines)] // exhaustive registration / runner
pub(crate) fn register_unix_socket(reg: &mut Registry<'_>) {
    register();
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
    let seqpacket_tests: &[(&str, &str, &str)] = &[
        (
            "stream_selfconnect",
            "stream-selfconnect",
            "STREAM_SELFCONNECT_OK",
        ),
        (
            "socketpair_boundary",
            "seqpacket-socketpair-boundary",
            "UDS_SEQPACKET_SOCKETPAIR_BOUNDARY_OK",
        ),
        (
            "multiple_messages",
            "seqpacket-socketpair-boundary",
            "UDS_SEQPACKET_SOCKETPAIR_BOUNDARY_OK",
        ),
        (
            "msg_trunc",
            "seqpacket-msg-trunc",
            "UDS_SEQPACKET_MSG_TRUNC_OK",
        ),
        (
            "shutdown",
            "seqpacket-shutdown",
            "UDS_SEQPACKET_SHUTDOWN_OK",
        ),
        (
            "fork_restore_inherit",
            "seqpacket-fork-restore-inherit",
            "UDS_SEQPACKET_FORK_RESTORE_INHERIT_OK",
        ),
    ];
    for &(name, sub, expected) in seqpacket_tests {
        let id = format!("UDS_SEQPACKET.{name}");
        let sub = sub.to_string();
        let expected = expected.to_string();
        reg.test("xworker", "unix_socket", id)
            .timeout(60)
            .build(move |cx| {
                let a = cx.require(AgentName::Dpg1);
                Box::new(move |run| {
                    Box::pin(async move {
                        let self_exe = run.self_exe().to_string();
                        let target = crate::binary_path(crate::BinaryType::PieGlibc, &self_exe);
                        let resp = run
                            .send_named_typed(
                                &a,
                                &EXEC_BIN,
                                ExecBinArgs {
                                    argv: vec![target, "unix-socket-test".into(), sub.clone()],
                                    timeout_ms: Some(10 * 1000),
                                    stdin: None,
                                    env: vec![],
                                },
                            )
                            .await;
                        let pass = matches!(&resp, Ok(out) if out.exit_code == 0 && out.stdout.contains(&*expected));
                        crate::coordinator::TestOutcome::new("A", pass, format!("{resp:?}"))
                    })
                })
            });
    }

    let seqpacket_scm_tests: &[(&str, &str, &str)] = &[
        (
            "pipe_pair_across_seqpacket",
            "seqpacket-scm-pipe-pair",
            "UDS_SEQPACKET_SCM_PIPE_PAIR_OK",
        ),
        (
            "file_across_seqpacket",
            "seqpacket-scm-file",
            "UDS_SEQPACKET_SCM_FILE_OK",
        ),
        (
            "msg_ctrunc",
            "seqpacket-scm-msg-ctrunc",
            "UDS_SEQPACKET_SCM_CTRUNC_OK",
        ),
    ];
    for &(name, sub, expected) in seqpacket_scm_tests {
        let id = format!("UDS_SEQPACKET_SCM.{name}");
        let sub = sub.to_string();
        let expected = expected.to_string();
        reg.test("xworker", "unix_socket", id)
            .timeout(60)
            .build(move |cx| {
                let a = cx.require(AgentName::Dpg1);
                Box::new(move |run| {
                    Box::pin(async move {
                        let self_exe = run.self_exe().to_string();
                        let target = crate::binary_path(crate::BinaryType::PieGlibc, &self_exe);
                        let resp = run
                            .send_named_typed(
                                &a,
                                &EXEC_BIN,
                                ExecBinArgs {
                                    argv: vec![target, "unix-socket-test".into(), sub.clone()],
                                    timeout_ms: Some(10 * 1000),
                                    stdin: None,
                                    env: Vec::new(),
                                },
                            )
                            .await;
                        let pass = matches!(&resp, Ok(out) if out.exit_code == 0 && out.stdout.contains(&*expected));
                        crate::coordinator::TestOutcome::new("A", pass, format!("{resp:?}"))
                    })
                })
            });
    }

    let dgram_scm_tests: &[(&str, &str, &str)] = &[
        (
            "pipe_pair_across_dgram",
            "dgram-scm-pipe-pair",
            "UDS_DGRAM_SCM_PIPE_PAIR_OK",
        ),
        (
            "file_across_dgram",
            "dgram-scm-file",
            "UDS_DGRAM_SCM_FILE_OK",
        ),
        (
            "msg_ctrunc",
            "dgram-scm-msg-ctrunc",
            "UDS_DGRAM_SCM_CTRUNC_OK",
        ),
        (
            "fork_restore_inherit",
            "dgram-scm-fork-restore",
            "UDS_DGRAM_SCM_FORK_RESTORE_OK",
        ),
    ];
    for &(name, sub, expected) in dgram_scm_tests {
        let id = format!("UDS_DGRAM_SCM.{name}");
        let sub = sub.to_string();
        let expected = expected.to_string();
        reg.test("xworker", "unix_socket", id)
            .timeout(60)
            .build(move |cx| {
                let a = cx.require(AgentName::Dpg1);
                Box::new(move |run| {
                    Box::pin(async move {
                        let self_exe = run.self_exe().to_string();
                        let target = crate::binary_path(crate::BinaryType::PieGlibc, &self_exe);
                        let resp = run
                            .send_named_typed(
                                &a,
                                &EXEC_BIN,
                                ExecBinArgs {
                                    argv: vec![target, "unix-socket-test".into(), sub.clone()],
                                    timeout_ms: Some(10 * 1000),
                                    stdin: None,
                                    env: Vec::new(),
                                },
                            )
                            .await;
                        let pass = matches!(&resp, Ok(out) if out.exit_code == 0 && out.stdout.contains(&*expected));
                        crate::coordinator::TestOutcome::new("A", pass, format!("{resp:?}"))
                    })
                })
            });
    }

    for &(name, sub, expected) in simple_tests {
        for &bt in crate::BinaryType::ALL {
            let id = format!("{name}.{}", bt.label());
            let sub = sub.to_string();
            let expected = expected.to_string();
            reg.test("xworker", "unix_socket", id)
                .timeout(60)
                .build(move |cx| {
                    let a = cx.require(AgentName::Dpg1);
                    Box::new(move |run| {
                        Box::pin(async move {
                            let self_exe = run.self_exe().to_string();
                            let target = crate::binary_path(bt, &self_exe);
                            // US3 (`bidirectional`) is registered as a
                            // top-level argv subcommand by
                            // `pipe_bridge::register_pipe_bridge`, so its
                            // argv is `[target, "bidirectional"]`.
                            // All other US tests are sub-subcommands of
                            // `unix-socket-test`.
                            let argv = if sub == "bidirectional" {
                                vec![target, sub.clone()]
                            } else {
                                vec![target, "unix-socket-test".into(), sub.clone()]
                            };
                            let resp = run
                                .send_named_typed(
                                    &a,
                                    &EXEC_BIN,
                                    ExecBinArgs {
                                        argv,
                                        timeout_ms: Some(10 * 1000),
                                        stdin: None,
                                        env: vec![],
                                    },
                                )
                                .await;
                            let pass = matches!(&resp, Ok(out) if out.exit_code == 0 && out.stdout.contains(&*expected));
                            crate::coordinator::TestOutcome::new("A", pass, format!("{resp:?}"))
                        })
                    })
                });
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
                        .send_named_typed(
                            &handle,
                            &EXEC_BIN,
                            ExecBinArgs {
                                argv: vec![
                                    target,
                                    "unix-socket-test".into(),
                                    "cross-process".into(),
                                ],
                                timeout_ms: Some(15 * 1000),
                                stdin: None,
                                env: vec![],
                            },
                        )
                        .await;
                    let pass = matches!(&resp, Ok(out) if out.exit_code == 0 && out.stdout.contains("US1_CROSS_PROCESS_OK"));
                    crate::coordinator::TestOutcome::new(&agent_label, pass, format!("{resp:?}"))
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
                        .send_named_typed(
                            &handle,
                            &EXEC_BIN,
                            ExecBinArgs {
                                argv: vec![
                                    target,
                                    "unix-socket-test".into(),
                                    "socketpair-fork-write".into(),
                                ],
                                timeout_ms: Some(15 * 1000),
                                stdin: None,
                                env: vec![],
                            },
                        )
                        .await;
                    let pass = matches!(&resp, Ok(out) if out.exit_code == 0 && out.stdout.contains("US6_SOCKETPAIR_FORK_OK"));
                    crate::coordinator::TestOutcome::new(&agent_label, pass, format!("{resp:?}"))
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
                        .send_named_typed(
                            &handle,
                            &EXEC_BIN,
                            ExecBinArgs {
                                argv: vec![
                                    target,
                                    "unix-socket-test".into(),
                                    "socketpair-fork-read".into(),
                                ],
                                timeout_ms: Some(15 * 1000),
                                stdin: None,
                                env: vec![],
                            },
                        )
                        .await;
                    let pass = matches!(&resp, Ok(out) if out.exit_code == 0 && out.stdout.contains("US6R_SOCKETPAIR_FORK_READ_OK"));
                    crate::coordinator::TestOutcome::new(&agent_label, pass, format!("{resp:?}"))
                }
            );

            // US6S: socketpair + child shutdown(SHUT_WR). Minimal repro
            // for the wave-6 W6-C5 fix (Copilot CLI / node child_process
            // spawnSync blocker). Captures the broker socketpair
            // shutdown() dispatch path.
            let agent_name = agent;
            let agent_label = agent.to_string();
            let id = format!("US6S.socketpair_shutdown.{}.{agent}", bt.label());
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
                        .send_named_typed(
                            &handle,
                            &EXEC_BIN,
                            ExecBinArgs {
                                argv: vec![
                                    target,
                                    "unix-socket-test".into(),
                                    "socketpair-shutdown".into(),
                                ],
                                timeout_ms: Some(15 * 1000),
                                stdin: None,
                                env: vec![],
                            },
                        )
                        .await;
                    let pass = matches!(&resp, Ok(out) if out.exit_code == 0 && out.stdout.contains("US6S_SOCKETPAIR_SHUTDOWN_OK"));
                    crate::coordinator::TestOutcome::new(&agent_label, pass, format!("{resp:?}"))
                }
            );

            // US6SP: socketpair + parent shutdown(SHUT_WR) followed by
            // reply read. Mirrors node libuv's exact pattern more
            // closely than US6S.
            let agent_name = agent;
            let agent_label = agent.to_string();
            let id = format!("US6SP.socketpair_shutdown_parent.{}.{agent}", bt.label());
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
                        .send_named_typed(
                            &handle,
                            &EXEC_BIN,
                            ExecBinArgs {
                                argv: vec![
                                    target,
                                    "unix-socket-test".into(),
                                    "socketpair-shutdown-parent".into(),
                                ],
                                timeout_ms: Some(15 * 1000),
                                stdin: None,
                                env: vec![],
                            },
                        )
                        .await;
                    let pass = matches!(&resp, Ok(out) if out.exit_code == 0 && out.stdout.contains("US6SP_SOCKETPAIR_SHUTDOWN_PARENT_OK"));
                    crate::coordinator::TestOutcome::new(&agent_label, pass, format!("{resp:?}"))
                }
            );
        }
    }

    for &(id, subcommand, ok_marker) in &[
        (
            "FET.socketpair_write.pie-glibc.dpg1",
            "socketpair-fork-write",
            "US6_SOCKETPAIR_FORK_OK",
        ),
        (
            "FET.socketpair_read.pie-glibc.dpg1",
            "socketpair-fork-read",
            "US6R_SOCKETPAIR_FORK_READ_OK",
        ),
        (
            "FET.socketpair_read_bare.pie-glibc.dpg1",
            "socketpair-fork-read-bare",
            "US6R_BARE_SOCKETPAIR_FORK_READ_OK",
        ),
    ] {
        typed_test!(
            reg,
            "xworker",
            "unix_socket",
            id,
            timeout = 60,
            agents[handle = AgentName::Dpg1],
            |run| {
                let self_exe = run.self_exe().to_string();
                let target = crate::binary_path(crate::BinaryType::PieGlibc, &self_exe);
                let resp = run
                    .send_named_typed(
                        &handle,
                        &EXEC_BIN,
                        ExecBinArgs {
                            argv: vec![target, "unix-socket-test".into(), subcommand.into()],
                            timeout_ms: Some(15 * 1000),
                            stdin: None,
                            env: vec![],
                        },
                    )
                    .await;
                let pass = matches!(&resp, Ok(out) if out.exit_code == 0 && out.stdout.contains(ok_marker));
                crate::coordinator::TestOutcome::new("dpg1", pass, format!("{resp:?}"))
            }
        );
    }

    for &bt in &[
        crate::BinaryType::StaticPieGlibc,
        crate::BinaryType::StaticPieMusl,
    ] {
        let id = format!("FET.socketpair_exec.{}.dpg1", bt.label());
        typed_test!(
            reg,
            "xworker",
            "unix_socket",
            id,
            timeout = 90,
            agents[handle = AgentName::Dpg1],
            |run| {
                let self_exe = run.self_exe().to_string();
                let target = crate::binary_path(bt, &self_exe);
                let resp = run
                    .send_named_typed(
                        &handle,
                        &EXEC_BIN,
                        ExecBinArgs {
                            argv: vec![target, "unix-socket-test".into(), "socketpair-exec".into()],
                            timeout_ms: Some(60 * 1000),
                            stdin: None,
                            env: vec![],
                        },
                    )
                    .await;
                let pass = matches!(&resp, Ok(out) if out.exit_code == 0 && out.stdout.contains("US6E_SOCKETPAIR_EXEC_OK"));
                crate::coordinator::TestOutcome::new("dpg1", pass, format!("{resp:?}"))
            }
        );
    }

    for &bt in &[
        crate::BinaryType::StaticPieMusl,
        crate::BinaryType::NonPieStaticMusl,
    ] {
        let id = format!("FET.fork_errno_touch.{}.dpg1", bt.label());
        typed_test!(
            reg,
            "xworker",
            "unix_socket",
            id,
            timeout = 60,
            agents[handle = AgentName::Dpg1],
            |run| {
                let self_exe = run.self_exe().to_string();
                let target = crate::binary_path(bt, &self_exe);
                let resp = run
                    .send_named_typed(
                        &handle,
                        &EXEC_BIN,
                        ExecBinArgs {
                            argv: vec![
                                target,
                                "unix-socket-test".into(),
                                "fork-errno-touch".into(),
                            ],
                            timeout_ms: Some(10 * 1000),
                            stdin: None,
                            env: vec![],
                        },
                    )
                    .await;
                let pass = matches!(&resp, Ok(out) if out.exit_code == 0 && out.stdout.contains("FET_FORK_ERRNO_TOUCH_OK"));
                crate::coordinator::TestOutcome::new("dpg1", pass, format!("{resp:?}"))
            }
        );
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
                        .send_named_typed(
                            &handle,
                            &EXEC_BIN,
                            ExecBinArgs {
                                argv: vec![
                                    target,
                                    "unix-socket-test".into(),
                                    "socketpair-exec".into(),
                                ],
                                timeout_ms: Some(30 * 1000),
                                stdin: None,
                                env: vec![],
                            },
                        )
                        .await;
                    let pass = matches!(&resp, Ok(out) if out.exit_code == 0 && out.stdout.contains("US6E_SOCKETPAIR_EXEC_OK"));
                    crate::coordinator::TestOutcome::new(&agent_label, pass, format!("{resp:?}"))
                }
            );
        }
    }
}

/// Minimal single-process named AF_UNIX stream rendezvous: socket → bind →
/// listen → (client) connect → accept → PING/PONG, all nonblocking in one
/// process. Isolates the broker named-stream state/protocol/shim path from the
/// cross-process fork/wake machinery the US* tests also exercise.
fn test_stream_selfconnect() -> i32 {
    let path = "/tmp/litebox-stream-selfconnect.sock";
    let _ = std::fs::remove_file(path);

    unsafe fn set_nonblock(fd: i32) {
        let fl = unsafe { libc::fcntl(fd, libc::F_GETFL, 0) };
        unsafe { libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK) };
    }

    fn make_sockaddr(path: &str) -> (libc::sockaddr_un, libc::socklen_t) {
        let mut addr: libc::sockaddr_un = unsafe { core::mem::zeroed() };
        addr.sun_family = libc::AF_UNIX as _;
        let bytes = path.as_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            addr.sun_path[i] = b as libc::c_char;
        }
        let len = (core::mem::size_of::<libc::sa_family_t>() + bytes.len() + 1) as libc::socklen_t;
        (addr, len)
    }

    let listener = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if listener < 0 {
        println!("STREAM_SELF_SOCKET_FAIL:errno={}", errno());
        return 1;
    }
    let (addr, len) = make_sockaddr(path);
    if unsafe { libc::bind(listener, (&raw const addr).cast(), len) } != 0 {
        println!("STREAM_SELF_BIND_FAIL:errno={}", errno());
        return 1;
    }
    if unsafe { libc::listen(listener, 4) } != 0 {
        println!("STREAM_SELF_LISTEN_FAIL:errno={}", errno());
        return 1;
    }
    unsafe { set_nonblock(listener) };

    let client = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if client < 0 {
        println!("STREAM_SELF_CLIENT_SOCKET_FAIL:errno={}", errno());
        return 1;
    }
    unsafe { set_nonblock(client) };
    let cr = unsafe { libc::connect(client, (&raw const addr).cast(), len) };
    if cr != 0 {
        let e = errno();
        if e != libc::EINPROGRESS && e != libc::EAGAIN {
            println!("STREAM_SELF_CONNECT_FAIL:errno={e}");
            return 1;
        }
    }

    // Accept (nonblocking poll loop).
    let mut conn = -1;
    for _ in 0..200 {
        conn = unsafe { libc::accept(listener, core::ptr::null_mut(), core::ptr::null_mut()) };
        if conn >= 0 {
            break;
        }
        let e = errno();
        if e != libc::EAGAIN && e != libc::EWOULDBLOCK {
            println!("STREAM_SELF_ACCEPT_FAIL:errno={e}");
            return 1;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    if conn < 0 {
        println!("STREAM_SELF_ACCEPT_TIMEOUT");
        return 1;
    }

    // client → conn: PING
    let ping = b"PING";
    let mut sent = false;
    for _ in 0..200 {
        let n = unsafe { libc::send(client, ping.as_ptr().cast(), ping.len(), 0) };
        if n == ping.len() as isize {
            sent = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    if !sent {
        println!("STREAM_SELF_SEND_FAIL:errno={}", errno());
        return 1;
    }
    let mut buf = [0u8; 16];
    let mut got = 0isize;
    for _ in 0..200 {
        got = unsafe { libc::recv(conn, buf.as_mut_ptr().cast(), buf.len(), 0) };
        if got > 0 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    if got != ping.len() as isize || &buf[..4] != ping {
        println!("STREAM_SELF_RECV_FAIL:got={got} errno={}", errno());
        return 1;
    }

    let _ = std::fs::remove_file(path);
    println!("STREAM_SELFCONNECT_OK");
    0
}

fn test_seqpacket_socketpair_boundary() -> i32 {
    let mut sv = [-1; 2];
    let rc = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            sv.as_mut_ptr(),
        )
    };
    if rc != 0 {
        println!("UDS_SEQPACKET_SOCKETPAIR_FAIL:errno={}", errno());
        return 1;
    }
    let a = sv[0];
    let b = sv[1];
    let _ = unsafe { libc::send(a, b"abc".as_ptr().cast(), 3, 0) };
    let _ = unsafe { libc::send(a, b"defgh".as_ptr().cast(), 5, 0) };
    let mut buf = [0u8; 16];
    let n1 = unsafe { libc::recv(b, buf.as_mut_ptr().cast(), buf.len(), 0) };
    let first = buf[..n1.max(0) as usize].to_vec();
    let n2 = unsafe { libc::recv(b, buf.as_mut_ptr().cast(), buf.len(), 0) };
    let second = buf[..n2.max(0) as usize].to_vec();
    unsafe {
        libc::close(a);
        libc::close(b);
    }
    if n1 == 3 && first == b"abc" && n2 == 5 && second == b"defgh" {
        println!("UDS_SEQPACKET_SOCKETPAIR_BOUNDARY_OK");
        0
    } else {
        println!("UDS_SEQPACKET_SOCKETPAIR_BOUNDARY_FAIL:n1={n1},n2={n2}");
        1
    }
}

fn test_seqpacket_msg_trunc() -> i32 {
    let mut sv = [-1; 2];
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            sv.as_mut_ptr(),
        )
    } != 0
    {
        println!("UDS_SEQPACKET_TRUNC_SOCKETPAIR_FAIL:{}", errno());
        return 1;
    }
    let a = sv[0];
    let b = sv[1];
    let _ = unsafe { libc::send(a, b"abcdef".as_ptr().cast(), 6, 0) };
    let mut buf = [0u8; 3];
    let n = unsafe { libc::recv(b, buf.as_mut_ptr().cast(), buf.len(), libc::MSG_TRUNC) };
    unsafe {
        libc::close(a);
        libc::close(b);
    }
    if n == 6 && &buf == b"abc" {
        println!("UDS_SEQPACKET_MSG_TRUNC_OK");
        0
    } else {
        println!("UDS_SEQPACKET_MSG_TRUNC_FAIL:n={n},buf={buf:?}");
        1
    }
}

fn test_seqpacket_shutdown() -> i32 {
    let mut sv = [-1; 2];
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            sv.as_mut_ptr(),
        )
    } != 0
    {
        println!("UDS_SEQPACKET_SHUTDOWN_SOCKETPAIR_FAIL:{}", errno());
        return 1;
    }
    let a = sv[0];
    let b = sv[1];
    let rc = unsafe { libc::shutdown(a, libc::SHUT_WR) };
    let n = unsafe { libc::send(a, b"x".as_ptr().cast(), 1, libc::MSG_NOSIGNAL) };
    let e = errno();
    unsafe {
        libc::close(a);
        libc::close(b);
    }
    if rc == 0 && n < 0 && e == libc::EPIPE {
        println!("UDS_SEQPACKET_SHUTDOWN_OK");
        0
    } else {
        println!("UDS_SEQPACKET_SHUTDOWN_FAIL:rc={rc},n={n},errno={e}");
        1
    }
}

fn test_seqpacket_fork_restore_inherit() -> i32 {
    let mut sv = [-1; 2];
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            sv.as_mut_ptr(),
        )
    } != 0
    {
        println!("UDS_SEQPACKET_FORK_SOCKETPAIR_FAIL:{}", errno());
        return 1;
    }
    let a = sv[0];
    let b = sv[1];
    let n = unsafe { libc::send(a, b"ping".as_ptr().cast(), 4, 0) };
    let send_errno = errno();
    if n != 4 {
        println!("UDS_SEQPACKET_FORK_RESTORE_INHERIT_SEND_FAIL:n={n},errno={send_errno}");
        unsafe {
            libc::close(a);
            libc::close(b);
        }
        return 1;
    }
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        println!("UDS_SEQPACKET_FORK_FAIL:{}", errno());
        return 1;
    }
    if pid == 0 {
        let mut buf = [0u8; 16];
        let n = unsafe { libc::recv(b, buf.as_mut_ptr().cast(), buf.len(), 0) };
        unsafe {
            libc::_exit(if n == 4 && &buf[..4] == b"ping" { 0 } else { 2 });
        }
    }
    let mut status = 0;
    unsafe {
        libc::waitpid(pid, &raw mut status, 0);
        libc::close(a);
    }
    let code = if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        99
    };
    if n == 4 && code == 0 {
        println!("UDS_SEQPACKET_FORK_RESTORE_INHERIT_OK");
        0
    } else {
        println!("UDS_SEQPACKET_FORK_RESTORE_INHERIT_FAIL:n={n},errno={send_errno},code={code}");
        1
    }
}

fn make_seqpacket_pair() -> Result<(i32, i32), String> {
    let mut sv = [-1; 2];
    // SAFETY: socketpair is called with valid constants and writes two fds on success.
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            sv.as_mut_ptr(),
        )
    } != 0
    {
        return Err(format!("socketpair: {}", errno()));
    }
    Ok((sv[0], sv[1]))
}

fn send_fd_seqpacket(sock: i32, fd_to_send: i32, payload: &[u8]) -> Result<isize, String> {
    let mut iov = libc::iovec {
        iov_base: payload.as_ptr().cast_mut().cast(),
        iov_len: payload.len(),
    };
    let mut control =
        vec![0u8; unsafe { libc::CMSG_SPACE(std::mem::size_of::<i32>() as u32) } as usize];
    // SAFETY: zeroed msghdr is filled with valid iov/control pointers before sendmsg.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = std::ptr::addr_of_mut!(iov);
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = control.len().try_into().unwrap();
    // SAFETY: msg_control points to a buffer of CMSG_SPACE(sizeof(i32)); CMSG_FIRSTHDR returns
    // a header within it, and the fd payload write targets exactly one i32 in that buffer.
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<i32>() as u32)
            .try_into()
            .unwrap();
        std::ptr::write(libc::CMSG_DATA(cmsg).cast::<i32>(), fd_to_send);
        let n = libc::sendmsg(sock, std::ptr::addr_of!(msg), 0);
        if n < 0 {
            Err(format!("sendmsg: {}", errno()))
        } else {
            Ok(n)
        }
    }
}

fn send_two_fds_seqpacket(sock: i32, fd1: i32, fd2: i32) -> Result<(), String> {
    let payload = b"xx";
    let mut iov = libc::iovec {
        iov_base: payload.as_ptr().cast_mut().cast(),
        iov_len: payload.len(),
    };
    let mut control =
        vec![0u8; unsafe { libc::CMSG_SPACE((2 * std::mem::size_of::<i32>()) as u32) } as usize];
    // SAFETY: zeroed msghdr is filled with valid iov/control pointers before sendmsg.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = std::ptr::addr_of_mut!(iov);
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = control.len().try_into().unwrap();
    // SAFETY: control buffer is sized for two i32 fds; writes stay within CMSG_DATA payload.
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN((2 * std::mem::size_of::<i32>()) as u32)
            .try_into()
            .unwrap();
        let data = libc::CMSG_DATA(cmsg).cast::<i32>();
        std::ptr::write(data, fd1);
        std::ptr::write(data.add(1), fd2);
        if libc::sendmsg(sock, std::ptr::addr_of!(msg), 0) < 0 {
            return Err(format!("sendmsg2: {}", errno()));
        }
    }
    Ok(())
}

fn test_seqpacket_scm_pipe_pair() -> i32 {
    match (|| -> Result<(), String> {
        let (left, right) = make_seqpacket_pair()?;
        let mut pipefd = [0; 2];
        // SAFETY: pipefd points to two writable i32 slots.
        if unsafe { libc::pipe(pipefd.as_mut_ptr()) } != 0 {
            return Err(format!("pipe: {}", errno()));
        }
        send_fd_seqpacket(left, pipefd[1], b"pipe")?;
        let (fds, _, _) = recv_fds_dgram(right, unsafe { libc::CMSG_SPACE(4) } as usize)?;
        if fds.len() != 1 {
            return Err(format!("fd count {}", fds.len()));
        }
        let byte = [b'Z'];
        // SAFETY: fds[0] is the received pipe write end; byte points to one readable byte.
        if unsafe { libc::write(fds[0], byte.as_ptr().cast(), 1) } != 1 {
            return Err(format!("write: {}", errno()));
        }
        let mut out = [0u8; 1];
        // SAFETY: pipefd[0] is the read end; out points to one writable byte.
        if unsafe { libc::read(pipefd[0], out.as_mut_ptr().cast(), 1) } != 1 || out[0] != b'Z' {
            return Err("pipe read mismatch".into());
        }
        for fd in [left, right, pipefd[0], pipefd[1], fds[0]] {
            unsafe { libc::close(fd) };
        }
        Ok(())
    })() {
        Ok(()) => {
            println!("UDS_SEQPACKET_SCM_PIPE_PAIR_OK");
            0
        }
        Err(e) => {
            println!("UDS_SEQPACKET_SCM_PIPE_PAIR_FAIL:{e}");
            1
        }
    }
}

fn test_seqpacket_scm_file() -> i32 {
    match (|| -> Result<(), String> {
        let (left, right) = make_seqpacket_pair()?;
        let file_path = format!(
            "/shared/litebox-uds-seqpacket-scm-file-{}",
            std::process::id()
        );
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&file_path)
            .map_err(|e| e.to_string())?;
        send_fd_seqpacket(left, file.as_raw_fd(), b"file")?;
        let (fds, _, _) = recv_fds_dgram(right, unsafe { libc::CMSG_SPACE(4) } as usize)?;
        if fds.len() != 1 {
            return Err(format!("fd count {}", fds.len()));
        }
        let data = b"abc";
        // SAFETY: fds[0] is a received writable file descriptor; data is readable.
        if unsafe { libc::write(fds[0], data.as_ptr().cast(), data.len()) } != data.len() as isize {
            return Err(format!("file write: {}", errno()));
        }
        // SAFETY: file fd is valid; lseek sets offset to start for verification.
        unsafe { libc::lseek(file.as_raw_fd(), 0, libc::SEEK_SET) };
        let mut s = String::new();
        std::io::Read::take(file, 3)
            .read_to_string(&mut s)
            .map_err(|e| e.to_string())?;
        if s != "abc" {
            return Err(format!("file contents {s:?}"));
        }
        for fd in [left, right, fds[0]] {
            unsafe { libc::close(fd) };
        }
        let _ = std::fs::remove_file(file_path);
        Ok(())
    })() {
        Ok(()) => {
            println!("UDS_SEQPACKET_SCM_FILE_OK");
            0
        }
        Err(e) => {
            println!("UDS_SEQPACKET_SCM_FILE_FAIL:{e}");
            1
        }
    }
}

fn test_seqpacket_scm_msg_ctrunc() -> i32 {
    match (|| -> Result<(), String> {
        let (left, right) = make_seqpacket_pair()?;
        let mut p1 = [0; 2];
        let mut p2 = [0; 2];
        // SAFETY: p1/p2 point to writable pipe fd arrays.
        if unsafe { libc::pipe(p1.as_mut_ptr()) } != 0
            || unsafe { libc::pipe(p2.as_mut_ptr()) } != 0
        {
            return Err(format!("pipe: {}", errno()));
        }
        send_two_fds_seqpacket(left, p1[1], p2[1])?;
        let (fds, flags, _) = recv_fds_dgram(right, unsafe { libc::CMSG_LEN(0) } as usize)?;
        if flags & libc::MSG_CTRUNC == 0 {
            return Err(format!("missing MSG_CTRUNC flags={flags}"));
        }
        if !fds.is_empty() {
            return Err(format!("fd count {}", fds.len()));
        }
        for fd in [left, right, p1[0], p1[1], p2[0], p2[1]] {
            unsafe { libc::close(fd) };
        }
        Ok(())
    })() {
        Ok(()) => {
            println!("UDS_SEQPACKET_SCM_CTRUNC_OK");
            0
        }
        Err(e) => {
            println!("UDS_SEQPACKET_SCM_CTRUNC_FAIL:{e}");
            1
        }
    }
}

fn unique_dgram_path(label: &str) -> String {
    format!("/run/litebox-uds-dgram-scm-{}-{label}", std::process::id())
}

fn make_dgram_pair(label: &str) -> Result<(i32, i32, String, String), String> {
    let left_path = unique_dgram_path(&format!("{label}-left"));
    let right_path = unique_dgram_path(&format!("{label}-right"));
    let _ = std::fs::remove_file(&left_path);
    let _ = std::fs::remove_file(&right_path);
    // SAFETY: socket is called with valid constants and returns an owned fd on success.
    let left = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM, 0) };
    if left < 0 {
        return Err(format!("socket left: {}", errno()));
    }
    // SAFETY: socket is called with valid constants and returns an owned fd on success.
    let right = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM, 0) };
    if right < 0 {
        // SAFETY: left is a live fd from socket above.
        unsafe { libc::close(left) };
        return Err(format!("socket right: {}", errno()));
    }
    bind_unix_dgram(left, &left_path)?;
    bind_unix_dgram(right, &right_path)?;
    Ok((left, right, left_path, right_path))
}

fn bind_unix_dgram(fd: i32, path: &str) -> Result<(), String> {
    let cpath = std::ffi::CString::new(path).map_err(|e| e.to_string())?;
    // SAFETY: zeroed sockaddr_un is immediately initialised below before use.
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let bytes = cpath.as_bytes_with_nul();
    if bytes.len() > addr.sun_path.len() {
        return Err("sockaddr path too long".into());
    }
    for (dst, src) in addr.sun_path.iter_mut().zip(bytes.iter().copied()) {
        *dst = src as libc::c_char;
    }
    let len = (std::mem::size_of::<libc::sa_family_t>() + bytes.len()) as libc::socklen_t;
    // SAFETY: addr points to a valid sockaddr_un with length covering sun_family and path.
    let rc = unsafe { libc::bind(fd, std::ptr::addr_of!(addr).cast(), len) };
    if rc != 0 {
        return Err(format!("bind {path}: {}", errno()));
    }
    Ok(())
}

fn send_fd_dgram(
    sock: i32,
    dest_path: &str,
    fd_to_send: i32,
    payload: &[u8],
) -> Result<isize, String> {
    let cpath = std::ffi::CString::new(dest_path).map_err(|e| e.to_string())?;
    // SAFETY: zeroed sockaddr_un is immediately initialised below before use.
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let path_bytes = cpath.as_bytes_with_nul();
    for (dst, src) in addr.sun_path.iter_mut().zip(path_bytes.iter().copied()) {
        *dst = src as libc::c_char;
    }
    let addr_len = (std::mem::size_of::<libc::sa_family_t>() + path_bytes.len()) as libc::socklen_t;
    let mut iov = libc::iovec {
        iov_base: payload.as_ptr().cast_mut().cast(),
        iov_len: payload.len(),
    };
    let mut control =
        vec![0u8; unsafe { libc::CMSG_SPACE(std::mem::size_of::<i32>() as u32) } as usize];
    // SAFETY: zeroed msghdr is filled with valid iov, name, and control pointers before sendmsg.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = std::ptr::addr_of_mut!(addr).cast();
    msg.msg_namelen = addr_len;
    msg.msg_iov = std::ptr::addr_of_mut!(iov);
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = control.len().try_into().unwrap();
    // SAFETY: msg_control points to a buffer of CMSG_SPACE(sizeof(i32)); CMSG_FIRSTHDR returns
    // a header within it, and the fd payload write targets exactly one i32 in that buffer.
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<i32>() as u32)
            .try_into()
            .unwrap();
        std::ptr::write(libc::CMSG_DATA(cmsg).cast::<i32>(), fd_to_send);
        let n = libc::sendmsg(sock, std::ptr::addr_of!(msg), 0);
        if n < 0 {
            Err(format!("sendmsg: {}", errno()))
        } else {
            Ok(n)
        }
    }
}

fn recv_fds_dgram(sock: i32, control_len: usize) -> Result<(Vec<i32>, i32, Vec<u8>), String> {
    let mut buf = [0u8; 64];
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: buf.len(),
    };
    let mut control = vec![0u8; control_len];
    // SAFETY: zeroed msghdr is filled with valid writable iov/control buffers before recvmsg.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = std::ptr::addr_of_mut!(iov);
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = control.len().try_into().unwrap();
    // SAFETY: msg points at valid writable buffers; recvmsg initialises msg fields and payload.
    let n = unsafe { libc::recvmsg(sock, std::ptr::addr_of_mut!(msg), 0) };
    if n < 0 {
        return Err(format!("recvmsg: {}", errno()));
    }
    let mut fds = Vec::new();
    // SAFETY: recvmsg populated msg_control/msg_controllen. The CMSG_* iteration macros stay
    // within that kernel-reported ancillary-data range.
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                let data_len = (*cmsg).cmsg_len as usize - libc::CMSG_LEN(0) as usize;
                let count = data_len / std::mem::size_of::<i32>();
                let data = libc::CMSG_DATA(cmsg).cast::<i32>();
                for i in 0..count {
                    fds.push(std::ptr::read(data.add(i)));
                }
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }
    Ok((fds, msg.msg_flags, buf[..n as usize].to_vec()))
}

fn test_dgram_scm_pipe_pair() -> i32 {
    match (|| -> Result<(), String> {
        let (left, right, left_path, right_path) = make_dgram_pair("pipe")?;
        let mut pipefd = [0; 2];
        // SAFETY: pipefd points to two writable i32 slots.
        if unsafe { libc::pipe(pipefd.as_mut_ptr()) } != 0 {
            return Err(format!("pipe: {}", errno()));
        }
        send_fd_dgram(left, &right_path, pipefd[1], b"pipe")?;
        let (fds, _, _) = recv_fds_dgram(right, unsafe { libc::CMSG_SPACE(4) } as usize)?;
        if fds.len() != 1 {
            return Err(format!("fd count {}", fds.len()));
        }
        let byte = [b'Z'];
        // SAFETY: fds[0] is the received pipe write end; byte points to one readable byte.
        if unsafe { libc::write(fds[0], byte.as_ptr().cast(), 1) } != 1 {
            return Err(format!("write: {}", errno()));
        }
        let mut out = [0u8; 1];
        // SAFETY: pipefd[0] is the read end; out points to one writable byte.
        if unsafe { libc::read(pipefd[0], out.as_mut_ptr().cast(), 1) } != 1 || out[0] != b'Z' {
            return Err("pipe read mismatch".into());
        }
        for fd in [left, right, pipefd[0], pipefd[1], fds[0]] {
            unsafe { libc::close(fd) };
        }
        let _ = std::fs::remove_file(left_path);
        let _ = std::fs::remove_file(right_path);
        Ok(())
    })() {
        Ok(()) => {
            println!("UDS_DGRAM_SCM_PIPE_PAIR_OK");
            0
        }
        Err(e) => {
            println!("UDS_DGRAM_SCM_PIPE_PAIR_FAIL:{e}");
            1
        }
    }
}

fn test_dgram_scm_file() -> i32 {
    match (|| -> Result<(), String> {
        let (left, right, left_path, right_path) = make_dgram_pair("file")?;
        let file_path = format!("/shared/litebox-uds-dgram-scm-file-{}", std::process::id());
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&file_path)
            .map_err(|e| e.to_string())?;
        send_fd_dgram(left, &right_path, file.as_raw_fd(), b"file")?;
        let (fds, _, _) = recv_fds_dgram(right, unsafe { libc::CMSG_SPACE(4) } as usize)?;
        if fds.len() != 1 {
            return Err(format!("fd count {}", fds.len()));
        }
        let data = b"abc";
        // SAFETY: fds[0] is a received writable file descriptor; data is readable.
        if unsafe { libc::write(fds[0], data.as_ptr().cast(), data.len()) } != data.len() as isize {
            return Err(format!("file write: {}", errno()));
        }
        // SAFETY: file fd is valid; lseek sets offset to start for verification.
        unsafe { libc::lseek(file.as_raw_fd(), 0, libc::SEEK_SET) };
        let mut s = String::new();
        std::io::Read::take(file, 3)
            .read_to_string(&mut s)
            .map_err(|e| e.to_string())?;
        if s != "abc" {
            return Err(format!("file contents {s:?}"));
        }
        for fd in [left, right, fds[0]] {
            unsafe { libc::close(fd) };
        }
        let _ = std::fs::remove_file(left_path);
        let _ = std::fs::remove_file(right_path);
        let _ = std::fs::remove_file(file_path);
        Ok(())
    })() {
        Ok(()) => {
            println!("UDS_DGRAM_SCM_FILE_OK");
            0
        }
        Err(e) => {
            println!("UDS_DGRAM_SCM_FILE_FAIL:{e}");
            1
        }
    }
}

fn test_dgram_scm_msg_ctrunc() -> i32 {
    match (|| -> Result<(), String> {
        let (left, right, left_path, right_path) = make_dgram_pair("ctrunc")?;
        let mut p1 = [0; 2];
        let mut p2 = [0; 2];
        // SAFETY: p1/p2 point to writable pipe fd arrays.
        if unsafe { libc::pipe(p1.as_mut_ptr()) } != 0
            || unsafe { libc::pipe(p2.as_mut_ptr()) } != 0
        {
            return Err(format!("pipe: {}", errno()));
        }
        send_two_fds_dgram(left, &right_path, p1[1], p2[1])?;
        let (fds, flags, _) = recv_fds_dgram(right, unsafe { libc::CMSG_LEN(0) } as usize)?;
        if flags & libc::MSG_CTRUNC == 0 {
            return Err(format!("missing MSG_CTRUNC flags={flags}"));
        }
        if !fds.is_empty() {
            return Err(format!("fd count {}", fds.len()));
        }
        for fd in [left, right, p1[0], p1[1], p2[0], p2[1]] {
            unsafe { libc::close(fd) };
        }
        let _ = std::fs::remove_file(left_path);
        let _ = std::fs::remove_file(right_path);
        Ok(())
    })() {
        Ok(()) => {
            println!("UDS_DGRAM_SCM_CTRUNC_OK");
            0
        }
        Err(e) => {
            println!("UDS_DGRAM_SCM_CTRUNC_FAIL:{e}");
            1
        }
    }
}

fn send_two_fds_dgram(sock: i32, dest_path: &str, fd1: i32, fd2: i32) -> Result<(), String> {
    let cpath = std::ffi::CString::new(dest_path).map_err(|e| e.to_string())?;
    // SAFETY: zeroed sockaddr_un is immediately initialised below before use.
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let path_bytes = cpath.as_bytes_with_nul();
    for (dst, src) in addr.sun_path.iter_mut().zip(path_bytes.iter().copied()) {
        *dst = src as libc::c_char;
    }
    let addr_len = (std::mem::size_of::<libc::sa_family_t>() + path_bytes.len()) as libc::socklen_t;
    let payload = b"xx";
    let mut iov = libc::iovec {
        iov_base: payload.as_ptr().cast_mut().cast(),
        iov_len: payload.len(),
    };
    let mut control =
        vec![0u8; unsafe { libc::CMSG_SPACE((2 * std::mem::size_of::<i32>()) as u32) } as usize];
    // SAFETY: zeroed msghdr is filled with valid iov/name/control pointers before sendmsg.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = std::ptr::addr_of_mut!(addr).cast();
    msg.msg_namelen = addr_len;
    msg.msg_iov = std::ptr::addr_of_mut!(iov);
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = control.len().try_into().unwrap();
    // SAFETY: control buffer is sized for two i32 fds; writes stay within CMSG_DATA payload.
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN((2 * std::mem::size_of::<i32>()) as u32)
            .try_into()
            .unwrap();
        let data = libc::CMSG_DATA(cmsg).cast::<i32>();
        std::ptr::write(data, fd1);
        std::ptr::write(data.add(1), fd2);
        if libc::sendmsg(sock, std::ptr::addr_of!(msg), 0) < 0 {
            return Err(format!("sendmsg2: {}", errno()));
        }
    }
    Ok(())
}

fn test_dgram_scm_fork_restore() -> i32 {
    match (|| -> Result<(), String> {
        let (left, right, left_path, right_path) = make_dgram_pair("fork")?;
        let mut pipefd = [0; 2];
        // SAFETY: pipefd points to two writable i32 slots.
        if unsafe { libc::pipe(pipefd.as_mut_ptr()) } != 0 {
            return Err(format!("pipe: {}", errno()));
        }
        send_fd_dgram(left, &right_path, pipefd[1], b"fork")?;
        let (fds, _, _) = recv_fds_dgram(right, unsafe { libc::CMSG_SPACE(4) } as usize)?;
        if fds.len() != 1 {
            return Err(format!("received fd count {}", fds.len()));
        }
        // SAFETY: fork creates a child inheriting the SCM_RIGHTS-received fd.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(format!("fork: {}", errno()));
        }
        if pid == 0 {
            let b = [b'F'];
            // SAFETY: fds[0] is the inherited pipe write end; b is one readable byte.
            let ok = unsafe { libc::write(fds[0], b.as_ptr().cast(), 1) } == 1;
            // SAFETY: child exits immediately without running parent destructors.
            unsafe { libc::_exit(if ok { 0 } else { 2 }) };
        }
        let mut out = [0u8; 1];
        // SAFETY: pipefd[0] is the read end and out points to one writable byte.
        if unsafe { libc::read(pipefd[0], out.as_mut_ptr().cast(), 1) } != 1 || out[0] != b'F' {
            return Err("fork pipe read mismatch".into());
        }
        let mut status = 0;
        // SAFETY: pid is the live child pid returned by fork.
        unsafe { libc::waitpid(pid, std::ptr::addr_of_mut!(status), 0) };
        let code = if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else {
            -1
        };
        if code != 0 {
            return Err(format!("child exit {code}"));
        }
        for fd in [left, right, pipefd[0], pipefd[1], fds[0]] {
            // SAFETY: all fds in this list are live parent-owned descriptors.
            unsafe { libc::close(fd) };
        }
        let _ = std::fs::remove_file(left_path);
        let _ = std::fs::remove_file(right_path);
        Ok(())
    })() {
        Ok(()) => {
            println!("UDS_DGRAM_SCM_FORK_RESTORE_OK");
            0
        }
        Err(e) => {
            println!("UDS_DGRAM_SCM_FORK_RESTORE_FAIL:{e}");
            1
        }
    }
}
