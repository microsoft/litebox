// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A port of `litebox_runner_vm_kernel/tests/linux/vsock_hybrid.host.py`, the host end of
//! `vsock_hybrid`, with the same scenarios in the same order. Fails by panicking.
//!
//! Hybrid vsock, over Unix sockets only: the guest's port P is reached by connecting to PATH and
//! sending `CONNECT P\n` (reply `OK <port>\n`, or a close if refused), and the host's port P is
//! the Unix socket `PATH_P`. No half-close.
//!
//! Shared by the Windows and macOS userland brokers' tests, which include it as a module.

use socket2::{Domain, SockAddr, Socket, Type};
use std::io::{ErrorKind, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

// As vsock_hybrid.rs's.
const PORT: u32 = 1024;
const SIGNAL_PORT: u32 = 1025;
const UNUSED_PORT: u32 = 1026;
const HOST_ECHO_PORT: u32 = 2000;
const HOST_REFUSING_PORT: u32 = 2001;
const MESSAGE: usize = 64;
const CONCURRENT: usize = 4;
const BULK: usize = 1024 * 1024;
const SHUT: &[u8] = b"shut";
/// The receive buffer, and the pause between receives, of the slow reader.
const SLOW_BUFFER: usize = 4096;
const SLOW_PAUSE: Duration = Duration::from_millis(1);
/// The longest a write, a read (for data or the end), or an accept waits.
const STEP_TIMEOUT: Duration = Duration::from_secs(60);
/// The pause between a read's polls.
const POLL_PAUSE: Duration = Duration::from_millis(1);

/// `PATH_<port>`.
fn port_path(path: &Path, port: u32) -> PathBuf {
    let mut port_path = path.as_os_str().to_owned();
    port_path.push(format!("_{port}"));
    port_path.into()
}

/// `PATH_P` listening for `HOST_ECHO_PORT`, and `PATH_Q` bound, not listening, for
/// `HOST_REFUSING_PORT`.
pub fn host_sockets(path: &Path) -> (Socket, Socket) {
    let listener = Socket::new(Domain::UNIX, Type::STREAM, None).unwrap();
    listener
        .bind(&SockAddr::unix(port_path(path, HOST_ECHO_PORT)).unwrap())
        .unwrap();
    listener.listen(1).unwrap();
    let refuser = Socket::new(Domain::UNIX, Type::STREAM, None).unwrap();
    refuser
        .bind(&SockAddr::unix(port_path(path, HOST_REFUSING_PORT)).unwrap())
        .unwrap();
    (listener, refuser)
}

/// Runs `vsock_hybrid`'s scenarios, once it is ready, then serves its connect on `listener`;
/// each in a thread named for it, which a failure's panic message shows.
pub fn run(path: &Path, listener: Socket) {
    let scenarios: [(&str, &(dyn Fn() + Sync)); 8] = [
        ("echo", &|| echo(path)),
        ("refused", &|| refused(path)),
        ("concurrent", &|| concurrent(path)),
        ("bulk", &|| bulk(path)),
        ("host_close", &|| host_close(path)),
        ("guest_close", &|| guest_close(path)),
        ("guest_shutdown", &|| guest_shutdown(path)),
        ("serve_guest", &|| serve_guest(&listener)),
    ];
    for (name, scenario) in scenarios {
        std::thread::scope(|scope| {
            std::thread::Builder::new()
                .name(name.to_owned())
                .spawn_scoped(scope, scenario)
                .unwrap();
        });
    }
}

fn pattern(length: usize, offset: usize) -> Vec<u8> {
    (offset..offset + length)
        .map(|i| u8::try_from((i * 7 + i / 4096) % 256).unwrap())
        .collect()
}

/// Connects to the guest's `port`; a close instead of the reply is `ConnectionRefused`.
fn connect(path: &Path, port: u32) -> std::io::Result<Socket> {
    let mut socket = Socket::new(Domain::UNIX, Type::STREAM, None)?;
    socket.set_write_timeout(Some(STEP_TIMEOUT))?;
    socket.connect(&SockAddr::unix(path)?)?;
    socket.write_all(format!("CONNECT {port}\n").as_bytes())?;
    // One byte at a time: what follows the line is the guest's.
    let mut reply = Vec::new();
    while !reply.ends_with(b"\n") {
        let mut byte = [0];
        if read(&socket, &mut byte)? == 0 {
            return Err(std::io::Error::new(
                ErrorKind::ConnectionRefused,
                format!("port {port} refused the connection"),
            ));
        }
        reply.push(byte[0]);
    }
    let host_port = reply
        .strip_prefix(b"OK ")
        .and_then(|rest| rest.strip_suffix(b"\n"));
    assert!(
        host_port.is_some_and(|digits| !digits.is_empty() && digits.iter().all(u8::is_ascii_digit)),
        "reply {:?} to CONNECT {port}",
        String::from_utf8_lossy(&reply)
    );
    Ok(socket)
}

/// Reads into `buffer` once data or the end arrives, within `STEP_TIMEOUT`.
///
/// Polls without blocking: on Windows, a blocking receive waiting as its peer's end arrives
/// can miss it, and one whose timeout expires as data arrives fails (`WSAEINTR`).
fn read(mut socket: &Socket, buffer: &mut [u8]) -> std::io::Result<usize> {
    socket.set_nonblocking(true)?;
    let deadline = Instant::now() + STEP_TIMEOUT;
    let read = loop {
        match socket.read(buffer) {
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    break Err(std::io::Error::new(
                        ErrorKind::TimedOut,
                        format!("no data or end in {STEP_TIMEOUT:?}"),
                    ));
                }
                std::thread::sleep(POLL_PAUSE);
            }
            read => break read,
        }
    };
    socket.set_nonblocking(false)?;
    read
}

fn read_exactly(socket: &Socket, length: usize, slow: bool) -> Vec<u8> {
    let mut data = vec![0; length];
    let mut got = 0;
    while got < length {
        if slow {
            std::thread::sleep(SLOW_PAUSE);
        }
        let end = length.min(got + if slow { SLOW_BUFFER } else { 65536 });
        let received = read(socket, &mut data[got..end]).unwrap();
        assert_ne!(received, 0, "EOF with {} bytes to read", length - got);
        got += received;
    }
    data
}

fn check_data(received: &[u8], expected: &[u8]) {
    assert_eq!(
        received.len(),
        expected.len(),
        "received {} bytes, expected {}",
        received.len(),
        expected.len()
    );
    if let Some(first) = received.iter().zip(expected).position(|(r, e)| r != e) {
        panic!("received data differs at byte {first}");
    }
}

fn check_eof(socket: &Socket) {
    let mut byte = [0];
    let received = read(socket, &mut byte).unwrap();
    assert_eq!(received, 0, "{:?} instead of EOF", &byte[..received]);
}

/// No data and no EOF yet.
fn check_open(mut socket: &Socket) {
    socket.set_nonblocking(true).unwrap();
    let result = socket.read(&mut [0]);
    socket.set_nonblocking(false).unwrap();
    match result {
        Err(error) if error.kind() == ErrorKind::WouldBlock => {}
        Err(error) => panic!("{error}"),
        Ok(0) => panic!("EOF before the close"),
        Ok(_) => panic!("data where nothing was sent"),
    }
}

fn echo(path: &Path) {
    let mut socket = connect(path, PORT).unwrap();
    socket.write_all(&pattern(MESSAGE, 0)).unwrap();
    check_data(&read_exactly(&socket, MESSAGE, false), &pattern(MESSAGE, 0));
}

fn refused(path: &Path) {
    match connect(path, UNUSED_PORT) {
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::ConnectionRefused | ErrorKind::ConnectionReset
            ) => {}
        Err(error) => panic!("{error}"),
        Ok(_) => panic!("connected to port {UNUSED_PORT}, where nothing listens"),
    }
}

fn concurrent(path: &Path) {
    let sockets: Vec<_> = (0..CONCURRENT)
        .map(|_| connect(path, PORT).unwrap())
        .collect();
    // All open before any sends.
    for (i, mut socket) in sockets.iter().enumerate().rev() {
        socket.write_all(&pattern(MESSAGE, i * MESSAGE)).unwrap();
    }
    for (i, socket) in sockets.into_iter().enumerate() {
        check_data(
            &read_exactly(&socket, MESSAGE, false),
            &pattern(MESSAGE, i * MESSAGE),
        );
    }
}

fn bulk(path: &Path) {
    let mut socket = connect(path, PORT).unwrap();
    socket.write_all(&pattern(BULK, 0)).unwrap();
    check_data(&read_exactly(&socket, BULK, true), &pattern(BULK, 0));
}

fn host_close(path: &Path) {
    let mut socket = connect(path, PORT).unwrap();
    socket.write_all(&pattern(MESSAGE, 0)).unwrap();
}

fn guest_close(path: &Path) {
    let mut socket = connect(path, PORT).unwrap();
    // The guest never reads this.
    socket.write_all(&pattern(MESSAGE, MESSAGE)).unwrap();
    check_data(&read_exactly(&socket, MESSAGE, false), &pattern(MESSAGE, 0));
    check_eof(&socket);
}

fn guest_shutdown(path: &Path) {
    let mut socket = connect(path, PORT).unwrap();
    let signal = connect(path, SIGNAL_PORT).unwrap();
    check_data(&read_exactly(&socket, MESSAGE, false), &pattern(MESSAGE, 0));
    // The guest shut down sending before it sent this.
    check_data(&read_exactly(&signal, SHUT.len(), false), SHUT);
    check_open(&socket);
    socket.write_all(&pattern(MESSAGE, MESSAGE)).unwrap();
    check_eof(&socket);
    drop(socket);
    drop(signal);
}

fn serve_guest(listener: &Socket) {
    let mut socket = accept(listener);
    let message = read_exactly(&socket, MESSAGE, false);
    check_data(&message, &pattern(MESSAGE, 2 * MESSAGE));
    socket.write_all(&message).unwrap();
}

/// Accepts within `STEP_TIMEOUT`, which Winsock's receive timeout does not bound.
fn accept(listener: &Socket) -> Socket {
    listener.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + STEP_TIMEOUT;
    let socket = loop {
        match listener.accept() {
            Ok((socket, _)) => break socket,
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                assert!(
                    Instant::now() < deadline,
                    "no connect to host port {HOST_ECHO_PORT}"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("{error}"),
        }
    };
    socket.set_nonblocking(false).unwrap();
    socket.set_write_timeout(Some(STEP_TIMEOUT)).unwrap();
    socket
}
