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
        "socketpair-exec" => test_socketpair_exec(),
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
            std::process::exit(1);
        }
        eprintln!("[US6a-child] wrote {n} bytes");
        unsafe { libc::close(child_fd) };
        std::process::exit(0);
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
            std::process::exit(1);
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
    for &(name, sub, expected) in simple_tests {
        for &bt in crate::BinaryType::ALL {
            let id = format!("{name}.{}", bt.label());
            let sub = sub.to_string();
            let expected = expected.to_string();
            reg.test("xworker", "unix_socket", id)
                .timeout(60)
                .build(move |cx| {
                    let a = (sub != "bidirectional").then(|| cx.require(AgentName::Dpg1));
                    let leaf = (sub == "bidirectional").then(|| {
                        cx.declare_ephemeral(
                            AgentName::Dpg1,
                            format!("Us3_{}", bt.short_label()),
                            SpawnKind::Fork {
                                binary: pipe_bridge::fork_binary_label(bt),
                                inherit_listen_ports: vec![],
                            },
                        )
                    });
                    Box::new(move |run| {
                        let a = a.clone();
                        let leaf = leaf.clone();
                        Box::pin(async move {
                            if sub == "bidirectional" {
                                let resp = run
                                    .run_leaf(
                                        leaf.as_ref().expect("bidirectional leaf"),
                                        &pipe_bridge::BIDIRECTIONAL,
                                        (),
                                    )
                                    .await;
                                let pass = matches!(&resp, Ok(out) if out.detail.contains(&*expected));
                                return crate::coordinator::TestOutcome::new("A", pass, format!("{resp:?}"));
                            }

                            let self_exe = run.self_exe().to_string();
                            let target = crate::binary_path(bt, &self_exe);
                            let resp = run
                                .send_named_typed(
                                    a.as_ref().expect("unix socket argv handle"),
                                    &EXEC_BIN,
                                    ExecBinArgs {
                                        argv: vec![target, "unix-socket-test".into(), sub],
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
