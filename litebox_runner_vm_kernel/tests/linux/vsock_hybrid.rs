// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! `AF_VSOCK` connections between the guest and `vsock_hybrid.host.py` over hybrid vsock (host
//! Unix sockets), which has no half-close: fixed-size messages and full closes only. Listens,
//! prints `ready`, serves the host's connections in order (see [`main`]), then connects to the
//! host's ports, and prints `vsock-hybrid ok`.
//!
//! A Linux program without libc, as Windows hosts have no Linux C toolchain, for x86_64 and
//! AArch64. Built static, as nothing applies its relocations:
//! `rustc --edition=2024 --target <arch>-unknown-none -C opt-level=2 -C relocation-model=static`.

#![no_std]
#![no_main]

use core::fmt::{self, Write as _};
use core::panic::PanicInfo;
use core::ptr;

// As vsock_hybrid.host.py's.
const PORT: u32 = 1024;
const SIGNAL_PORT: u32 = 1025;
const HOST_ECHO_PORT: u32 = 2000;
const HOST_REFUSING_PORT: u32 = 2001;
const MESSAGE: usize = 64;
const CONCURRENT: usize = 4;
const BULK: usize = 1024 * 1024;
const SHUT: &[u8] = b"shut";

const STDOUT: i32 = 1;
const AF_VSOCK: u16 = 40;
const SOCK_STREAM: i32 = 1;
const SOL_SOCKET: i32 = 1;
const SO_ERROR: i32 = 4;
const SHUT_WR: i32 = 1;
const POLLIN: i16 = 1;
const MSG_NOSIGNAL: i32 = 0x4000;
const VMADDR_CID_ANY: u32 = u32::MAX;
const VMADDR_CID_HOST: u32 = 2;
const EPIPE: i32 = 32;
const ECONNRESET: i32 = 104;
const ETIMEDOUT: i32 = 110;

fn pattern(i: usize) -> u8 {
    (i * 7 + i / 4096) as u8
}

fn read_exactly(fd: i32, buffer: &mut [u8]) {
    let mut got = 0;
    while got < buffer.len() {
        let n = read(fd, &mut buffer[got..]).unwrap();
        assert!(n > 0);
        got += n;
    }
}

fn write_all(fd: i32, buffer: &[u8]) {
    let mut done = 0;
    while done < buffer.len() {
        let n = write(fd, &buffer[done..]).unwrap();
        assert!(n > 0);
        done += n;
    }
}

fn check_pattern(buffer: &[u8], offset: usize) {
    for (i, &byte) in buffer.iter().enumerate() {
        assert_eq!(byte, pattern(offset + i));
    }
}

fn fill_pattern(buffer: &mut [u8], offset: usize) {
    for (i, byte) in buffer.iter_mut().enumerate() {
        *byte = pattern(offset + i);
    }
}

/// Waits for the host's close.
fn read_eof(fd: i32) {
    assert_eq!(read(fd, &mut [0]), Ok(0));
}

fn listen_on(port: u32) -> i32 {
    let fd = socket(AF_VSOCK, SOCK_STREAM, 0).unwrap();
    bind(fd, &SockaddrVm::new(VMADDR_CID_ANY, port)).unwrap();
    listen(fd, 8).unwrap();
    fd
}

fn accept_host(listener: i32) -> i32 {
    let mut peer = SockaddrVm::default();
    let (fd, len) = accept(listener, &mut peer).unwrap();
    assert_eq!(len as usize, size_of::<SockaddrVm>());
    assert_eq!(peer.family, AF_VSOCK);
    assert_eq!(peer.cid, VMADDR_CID_HOST);
    fd
}

fn serve_echo(listener: i32) {
    let mut buffer = [0; MESSAGE];
    let fd = accept_host(listener);
    read_exactly(fd, &mut buffer);
    write_all(fd, &buffer);
    read_eof(fd);
    close(fd).unwrap();
}

/// CONCURRENT connections at once, each echoed once its message is complete.
fn serve_concurrent(listener: i32) {
    let fds: [i32; CONCURRENT] = core::array::from_fn(|_| accept_host(listener));
    let mut data = [[0; MESSAGE]; CONCURRENT];
    let mut got = [0; CONCURRENT];
    let mut pending = CONCURRENT;
    while pending > 0 {
        let mut polls: [PollFd; CONCURRENT] = core::array::from_fn(|i| PollFd {
            fd: if got[i] < MESSAGE { fds[i] } else { -1 },
            events: POLLIN,
            revents: 0,
        });
        let ready = poll(&mut polls).unwrap();
        assert!(ready > 0);
        for (i, poll) in polls.iter().enumerate() {
            if poll.revents == 0 {
                continue;
            }
            let n = read(fds[i], &mut data[i][got[i]..]).unwrap();
            assert!(n > 0);
            got[i] += n;
            if got[i] == MESSAGE {
                write_all(fds[i], &data[i]);
                pending -= 1;
            }
        }
    }
    for fd in fds {
        read_eof(fd);
        close(fd).unwrap();
    }
}

/// BULK bytes each way, in turn; the host reads slowly.
fn serve_bulk(listener: i32) {
    let mut buffer = [0; 64 * 1024];
    let fd = accept_host(listener);
    let mut done = 0;
    while done < BULK {
        let len = buffer.len().min(BULK - done);
        let n = read(fd, &mut buffer[..len]).unwrap();
        assert!(n > 0);
        check_pattern(&buffer[..n], done);
        done += n;
    }
    for done in (0..BULK).step_by(buffer.len()) {
        fill_pattern(&mut buffer, done);
        write_all(fd, &buffer);
    }
    read_eof(fd);
    close(fd).unwrap();
}

/// The host sends a message and closes.
fn serve_host_close(listener: i32) {
    let mut buffer = [0; MESSAGE];
    let fd = accept_host(listener);
    read_exactly(fd, &mut buffer);
    check_pattern(&buffer, 0);
    read_eof(fd);
    assert_eq!(send(fd, b"x", MSG_NOSIGNAL), Err(EPIPE));
    close(fd).unwrap();
}

/// Replies and closes with the host's message unread, which must not reset the host's end.
fn serve_guest_close(listener: i32) {
    let mut buffer = [0; MESSAGE];
    let fd = accept_host(listener);
    let mut polls = [PollFd {
        fd,
        events: POLLIN,
        revents: 0,
    }];
    assert_eq!(poll(&mut polls), Ok(1));
    assert_eq!(polls[0].revents, POLLIN);
    fill_pattern(&mut buffer, 0);
    write_all(fd, &buffer);
    close(fd).unwrap();
}

/// After this end's `SHUT_WR`, signalled on a second connection, the host still sends, and sees
/// EOF only at the close.
fn serve_shutdown(listener: i32, signal_listener: i32) {
    let mut buffer = [0; MESSAGE];
    let fd = accept_host(listener);
    let signal_fd = accept_host(signal_listener);
    fill_pattern(&mut buffer, 0);
    write_all(fd, &buffer);
    shutdown(fd, SHUT_WR).unwrap();
    write_all(signal_fd, SHUT);
    read_exactly(fd, &mut buffer);
    check_pattern(&buffer, MESSAGE);
    close(fd).unwrap();
    read_eof(signal_fd);
    close(signal_fd).unwrap();
}

fn so_error(fd: i32) -> i32 {
    let mut error = -1;
    let len = getsockopt(fd, SOL_SOCKET, SO_ERROR, &mut error).unwrap();
    assert_eq!(len as usize, size_of::<i32>());
    error
}

/// The host echoes a message on its listening port and closes; a connect to the other is reset
/// (ECONNRESET, left pending), as by Firecracker, or times out (ETIMEDOUT) under
/// vhost-device-vsock 0.3.0, which never answers it.
fn connect_host_ports() {
    let mut buffer = [0; MESSAGE];
    let fd = socket(AF_VSOCK, SOCK_STREAM, 0).unwrap();
    let mut address = SockaddrVm::new(VMADDR_CID_HOST, HOST_ECHO_PORT);
    connect(fd, &address).unwrap();
    fill_pattern(&mut buffer, 2 * MESSAGE);
    write_all(fd, &buffer);
    read_exactly(fd, &mut buffer);
    check_pattern(&buffer, 2 * MESSAGE);
    read_eof(fd);
    close(fd).unwrap();

    let fd = socket(AF_VSOCK, SOCK_STREAM, 0).unwrap();
    address.port = HOST_REFUSING_PORT;
    let error = connect(fd, &address).unwrap_err();
    assert!(matches!(error, ECONNRESET | ETIMEDOUT), "errno {error}");
    if error == ECONNRESET {
        assert_eq!(so_error(fd), ECONNRESET);
    }
    assert_eq!(so_error(fd), 0);
    close(fd).unwrap();
}

fn main() -> ! {
    let listener = listen_on(PORT);
    let signal_listener = listen_on(SIGNAL_PORT);
    Stdout.write_str("ready\n").unwrap();
    serve_echo(listener);
    serve_concurrent(listener);
    serve_bulk(listener);
    serve_host_close(listener);
    serve_guest_close(listener);
    serve_shutdown(listener, signal_listener);
    close(listener).unwrap();
    close(signal_listener).unwrap();
    connect_host_ports();
    Stdout.write_str("vsock-hybrid ok\n").unwrap();
    exit_group(0)
}

#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    let _ = writeln!(Stdout, "FAIL {info}");
    exit_group(1)
}

#[cfg(target_arch = "x86_64")]
#[unsafe(naked)]
#[unsafe(no_mangle)]
extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "xor ebp, ebp",
        "and rsp, -16",
        "call {main}",
        "ud2",
        main = sym main,
    );
}

#[cfg(target_arch = "aarch64")]
#[unsafe(naked)]
#[unsafe(no_mangle)]
extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "mov x29, xzr",
        "mov x30, xzr",
        "bl {main}",
        "brk #0",
        main = sym main,
    );
}

struct Stdout;

impl fmt::Write for Stdout {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let mut bytes = s.as_bytes();
        while !bytes.is_empty() {
            let Ok(n @ 1..) = write(STDOUT, bytes) else {
                return Err(fmt::Error);
            };
            bytes = &bytes[n..];
        }
        Ok(())
    }
}

/// `struct sockaddr_vm`.
#[repr(C)]
#[derive(Default)]
struct SockaddrVm {
    family: u16,
    reserved1: u16,
    port: u32,
    cid: u32,
    flags: u8,
    zero: [u8; 3],
}

impl SockaddrVm {
    fn new(cid: u32, port: u32) -> Self {
        Self {
            family: AF_VSOCK,
            port,
            cid,
            ..Self::default()
        }
    }
}

/// `struct pollfd`.
#[repr(C)]
struct PollFd {
    fd: i32,
    events: i16,
    revents: i16,
}

#[cfg(target_arch = "x86_64")]
mod nr {
    pub const READ: usize = 0;
    pub const WRITE: usize = 1;
    pub const CLOSE: usize = 3;
    pub const SOCKET: usize = 41;
    pub const CONNECT: usize = 42;
    pub const ACCEPT: usize = 43;
    pub const SENDTO: usize = 44;
    pub const SHUTDOWN: usize = 48;
    pub const BIND: usize = 49;
    pub const LISTEN: usize = 50;
    pub const GETSOCKOPT: usize = 55;
    pub const PPOLL: usize = 271;
    pub const EXIT_GROUP: usize = 231;
}

#[cfg(target_arch = "aarch64")]
mod nr {
    pub const READ: usize = 63;
    pub const WRITE: usize = 64;
    pub const CLOSE: usize = 57;
    pub const SOCKET: usize = 198;
    pub const CONNECT: usize = 203;
    pub const ACCEPT: usize = 202;
    pub const SENDTO: usize = 206;
    pub const SHUTDOWN: usize = 210;
    pub const BIND: usize = 200;
    pub const LISTEN: usize = 201;
    pub const GETSOCKOPT: usize = 209;
    pub const PPOLL: usize = 73;
    pub const EXIT_GROUP: usize = 94;
}

/// Syscall `nr` with `args`, and zeros for the rest: its value, or its errno.
///
/// # Safety
///
/// `args` must be as the syscall requires, e.g., pointers valid for what it accesses.
unsafe fn syscall<const N: usize>(nr: usize, args: [usize; N]) -> Result<usize, i32> {
    let arg = |i: usize| args.get(i).copied().unwrap_or(0);
    let ret: isize;
    // SAFETY: the caller guarantees the syscall's requirements; `syscall` clobbers only rcx and
    // r11, besides rax, and not the stack.
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") nr as isize => ret,
            in("rdi") arg(0),
            in("rsi") arg(1),
            in("rdx") arg(2),
            in("r10") arg(3),
            in("r8") arg(4),
            in("r9") arg(5),
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    // SAFETY: the caller guarantees the syscall's requirements; `svc #0` clobbers only x0, and
    // not the stack.
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") nr,
            inlateout("x0") arg(0) as isize => ret,
            in("x1") arg(1),
            in("x2") arg(2),
            in("x3") arg(3),
            in("x4") arg(4),
            in("x5") arg(5),
            options(nostack),
        );
    }
    // Linux returns errors as -4095..=-1.
    match ret {
        -4095..=-1 => Err(-ret as i32),
        _ => Ok(ret as usize),
    }
}

fn read(fd: i32, buffer: &mut [u8]) -> Result<usize, i32> {
    // SAFETY: `buffer` is writable for its length.
    unsafe {
        syscall(
            nr::READ,
            [fd as usize, buffer.as_mut_ptr() as usize, buffer.len()],
        )
    }
}

fn write(fd: i32, buffer: &[u8]) -> Result<usize, i32> {
    // SAFETY: `buffer` is readable for its length.
    unsafe {
        syscall(
            nr::WRITE,
            [fd as usize, buffer.as_ptr() as usize, buffer.len()],
        )
    }
}

fn close(fd: i32) -> Result<usize, i32> {
    // SAFETY: close takes no pointers, and this program owns no fds but those it opened.
    unsafe { syscall(nr::CLOSE, [fd as usize]) }
}

fn socket(family: u16, kind: i32, protocol: i32) -> Result<i32, i32> {
    // SAFETY: socket takes no pointers.
    unsafe {
        syscall(
            nr::SOCKET,
            [family.into(), kind as usize, protocol as usize],
        )
    }
    .map(|fd| fd as i32)
}

fn bind(fd: i32, address: &SockaddrVm) -> Result<usize, i32> {
    // SAFETY: `address` is readable for its size.
    unsafe {
        syscall(
            nr::BIND,
            [
                fd as usize,
                ptr::from_ref(address) as usize,
                size_of::<SockaddrVm>(),
            ],
        )
    }
}

fn listen(fd: i32, backlog: i32) -> Result<usize, i32> {
    // SAFETY: listen takes no pointers.
    unsafe { syscall(nr::LISTEN, [fd as usize, backlog as usize]) }
}

/// The accepted fd, and the length of the peer's address, written to `peer`.
fn accept(fd: i32, peer: &mut SockaddrVm) -> Result<(i32, u32), i32> {
    let mut len = size_of::<SockaddrVm>() as u32;
    // SAFETY: `peer` is writable for `len` bytes, and `len` is writable.
    unsafe {
        syscall(
            nr::ACCEPT,
            [
                fd as usize,
                ptr::from_mut(peer) as usize,
                &raw mut len as usize,
            ],
        )
    }
    .map(|fd| (fd as i32, len))
}

fn connect(fd: i32, address: &SockaddrVm) -> Result<usize, i32> {
    // SAFETY: `address` is readable for its size.
    unsafe {
        syscall(
            nr::CONNECT,
            [
                fd as usize,
                ptr::from_ref(address) as usize,
                size_of::<SockaddrVm>(),
            ],
        )
    }
}

fn send(fd: i32, buffer: &[u8], flags: i32) -> Result<usize, i32> {
    // SAFETY: `buffer` is readable for its length, and the null address is none.
    unsafe {
        syscall(
            nr::SENDTO,
            [
                fd as usize,
                buffer.as_ptr() as usize,
                buffer.len(),
                flags as usize,
                0,
                0,
            ],
        )
    }
}

fn shutdown(fd: i32, how: i32) -> Result<usize, i32> {
    // SAFETY: shutdown takes no pointers.
    unsafe { syscall(nr::SHUTDOWN, [fd as usize, how as usize]) }
}

/// The length of the option's value, written to `value`.
fn getsockopt(fd: i32, level: i32, name: i32, value: &mut i32) -> Result<u32, i32> {
    let mut len = size_of::<i32>() as u32;
    // SAFETY: `value` is writable for `len` bytes, and `len` is writable.
    unsafe {
        syscall(
            nr::GETSOCKOPT,
            [
                fd as usize,
                level as usize,
                name as usize,
                ptr::from_mut(value) as usize,
                &raw mut len as usize,
            ],
        )
    }
    .map(|_| len)
}

/// Waits for an event of `fds` without a timeout. ppoll, as AArch64 has no poll.
fn poll(fds: &mut [PollFd]) -> Result<usize, i32> {
    // SAFETY: `fds` is writable for its length, and the null timeout and signal mask are none.
    unsafe { syscall(nr::PPOLL, [fds.as_mut_ptr() as usize, fds.len(), 0, 0, 0]) }
}

fn exit_group(status: i32) -> ! {
    // SAFETY: exit_group takes no pointers.
    let _ = unsafe { syscall(nr::EXIT_GROUP, [status as usize]) };
    unreachable!("exit_group returned")
}
