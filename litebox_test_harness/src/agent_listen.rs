// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! TCP variant of the agent. Listens on a TCP port, accepts one connection,
//! and runs the standard agent protocol over that connection.
//!
//! This enables host-side tests: the integration test (running outside the
//! sandbox) connects to a forwarded port and drives the agent with the same
//! JSON protocol used over pipes.
//!
//! Implementation: dup2 the accepted TCP socket onto stdin (fd 0) and
//! stdout (fd 1), then call the existing agent loop unchanged. This avoids
//! modifying the 60+ `respond()` call sites in agent.rs.

use std::net::TcpListener;
use std::os::unix::io::AsRawFd;

/// Listen on `port`, accept one connection, redirect stdin/stdout to it,
/// then run the standard agent loop.
pub fn run(self_exe: &str, port: u16) {
    let listener = TcpListener::bind(format!("0.0.0.0:{port}"))
        .unwrap_or_else(|e| panic!("agent-listen: bind 0.0.0.0:{port} failed: {e}"));
    eprintln!("[agent-listen] listening on port {port}");

    let (stream, peer) = listener
        .accept()
        .unwrap_or_else(|e| panic!("agent-listen: accept failed: {e}"));
    eprintln!("[agent-listen] accepted connection from {peer}");

    // Drop the listener — we only handle one connection.
    drop(listener);

    let fd = stream.as_raw_fd();

    // SAFETY: dup2 is a standard POSIX call. We redirect stdin and stdout
    // to the TCP socket so the existing agent_loop (which reads stdin and
    // writes stdout) transparently works over TCP.
    unsafe {
        if libc::dup2(fd, 0) < 0 {
            panic!("agent-listen: dup2 to stdin failed");
        }
        if libc::dup2(fd, 1) < 0 {
            panic!("agent-listen: dup2 to stdout failed");
        }
        // Close the original fd (now duplicated onto 0 and 1).
        if fd > 2 {
            libc::close(fd);
        }
    }

    // Forget the stream so it isn't closed when dropped (fds 0/1 own it now).
    std::mem::forget(stream);

    // Run the standard agent loop — it reads from fd 0 and writes to fd 1.
    crate::agent::run(self_exe);
}
