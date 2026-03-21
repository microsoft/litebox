// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! WinSock syscall handlers for the NT shim.
//!
//! Each ws2_32.dll export is a syscall trampoline that enters the shim with
//! a `WS2_*` syscall number (0x1200+). This module maps those numbers to
//! operations on the litebox smoltcp `Network` stack.
//!
//! ## Socket storage
//!
//! Socket FDs (`litebox::net::SocketFd<Platform>`) are not clonable. We store
//! them in `NtSharedState::sockets` keyed by an integer socket ID, and the NT
//! handle table stores `NtObject::Socket { sock_id }` to map HANDLEs to socket
//! IDs. Operations borrow the SocketFd through the sockets table.
//!
//! ## WinSock return value convention
//!
//! Most functions return `SOCKET_ERROR` (−1) on failure and set the per-thread
//! error code via `WSAGetLastError()` (TEB offset 0x68). `socket()` returns
//! `INVALID_SOCKET` (usize::MAX) on failure. `WSAStartup()` returns an error
//! code directly.

use super::NtSyscallArgs;
use crate::{ExecutionContext, NtSharedState, NtStatus};
use litebox_common_windows::stub_dlls;

/// `SOCKET_ERROR` / `INVALID_SOCKET` return value.
const SOCKET_ERROR: usize = usize::MAX;
const INVALID_SOCKET: usize = SOCKET_ERROR;

// WinSock error codes (subset for initial implementation).
const WSANOTINITIALISED: u32 = 10093;
const WSAEAFNOSUPPORT: u32 = 10047;
const WSAENOTSOCK: u32 = 10038;
const WSAECONNREFUSED: u32 = 10061;
const WSAETIMEDOUT: u32 = 10060;
const WSAEINVAL: u32 = 10022;
const WSAENETUNREACH: u32 = 10051;
const WSAENOTCONN: u32 = 10057;
const WSAHOST_NOT_FOUND: u32 = 11001;
const WSAEADDRINUSE: u32 = 10048;
const WSAEADDRNOTAVAIL: u32 = 10049;
const WSAEMFILE: u32 = 10024;
const WSAESHUTDOWN: u32 = 10058;
const WSAECONNRESET: u32 = 10054;

/// Set the per-thread WinSock error code (TEB.LastErrorValue at offset 0x68).
fn set_last_wsa_error(teb_va: usize, code: u32) {
    if teb_va != 0 {
        // Safety: guest TEB is directly accessible in userland platforms.
        unsafe {
            core::ptr::write(
                (teb_va + crate::peb_teb::teb_offsets::LAST_ERROR) as *mut u32,
                code,
            );
        }
    }
}

/// Return SOCKET_ERROR and set WSA error code.
fn wsa_fail(ctx: &mut ExecutionContext, teb_va: usize, code: u32) -> (NtStatus, bool) {
    set_last_wsa_error(teb_va, code);
    ctx.regs.rax = SOCKET_ERROR;
    (NtStatus::STATUS_SUCCESS, false)
}

/// Return a success value in rax.
fn wsa_ok(ctx: &mut ExecutionContext, teb_va: usize, value: usize) -> (NtStatus, bool) {
    set_last_wsa_error(teb_va, 0);
    ctx.regs.rax = value;
    (NtStatus::STATUS_SUCCESS, false)
}

/// Dispatch a WS2_* syscall number.
///
/// Returns `(NtStatus, should_terminate)`. The caller must NOT overwrite rax
/// after this returns — WinSock return values are set in rax by the handlers.
pub(crate) fn dispatch_ws2_syscall(
    shared: &NtSharedState,
    nr: u32,
    ctx: &mut ExecutionContext,
    teb_va: usize,
) -> (NtStatus, bool) {
    match nr {
        stub_dlls::WS2_STARTUP => ws2_startup(ctx, teb_va),
        stub_dlls::WS2_CLEANUP => ws2_cleanup(ctx, teb_va),
        stub_dlls::WS2_SOCKET => ws2_socket(shared, ctx, teb_va),
        stub_dlls::WS2_CLOSESOCKET => ws2_closesocket(shared, ctx, teb_va),
        stub_dlls::WS2_CONNECT => ws2_connect(shared, ctx, teb_va),
        stub_dlls::WS2_SEND => ws2_send(shared, ctx, teb_va),
        stub_dlls::WS2_RECV => ws2_recv(shared, ctx, teb_va),
        stub_dlls::WS2_BIND => ws2_bind(shared, ctx, teb_va),
        stub_dlls::WS2_LISTEN => ws2_listen(shared, ctx, teb_va),
        stub_dlls::WS2_ACCEPT => ws2_accept(shared, ctx, teb_va),
        stub_dlls::WS2_SHUTDOWN => ws2_shutdown(shared, ctx, teb_va),
        stub_dlls::WS2_SETSOCKOPT => ws2_setsockopt(shared, ctx, teb_va),
        stub_dlls::WS2_GETSOCKOPT => ws2_getsockopt(ctx, teb_va),
        stub_dlls::WS2_IOCTLSOCKET => ws2_ioctlsocket(ctx, teb_va),
        stub_dlls::WS2_SELECT => ws2_select(ctx, teb_va),
        stub_dlls::WS2_GETSOCKNAME => ws2_getsockname(shared, ctx, teb_va),
        stub_dlls::WS2_GETPEERNAME => ws2_getpeername(shared, ctx, teb_va),
        stub_dlls::WS2_GETADDRINFO => ws2_getaddrinfo(shared, ctx, teb_va),
        stub_dlls::WS2_FREEADDRINFO => ws2_freeaddrinfo(ctx, teb_va),
        stub_dlls::WS2_SENDTO => ws2_sendto(shared, ctx, teb_va),
        stub_dlls::WS2_RECVFROM => ws2_recvfrom(shared, ctx, teb_va),
        stub_dlls::WS2_INET_PTON => ws2_inet_pton(ctx, teb_va),
        _ => {
            log_unimplemented!("unknown WS2 syscall nr=0x{:04X}", nr);
            wsa_fail(ctx, teb_va, WSANOTINITIALISED)
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers: socket table access
// ---------------------------------------------------------------------------

/// Look up the socket ID for a WinSock SOCKET handle value.
/// Returns `None` if the handle doesn't exist or isn't a socket.
fn sock_id_for_handle(shared: &NtSharedState, handle: u32) -> Option<u32> {
    let handles = shared.handles.lock();
    match handles.get(handle) {
        Some(crate::handle_table::NtObject::Socket { sock_id }) => Some(*sock_id),
        _ => None,
    }
}

/// Allocate a new socket ID and insert the SocketFd into the socket table.
/// Returns the allocated socket ID.
fn insert_socket(shared: &NtSharedState, fd: litebox::net::SocketFd<crate::Platform>) -> u32 {
    let mut next = shared.next_socket_id.lock();
    let id = *next;
    *next = next.wrapping_add(1);
    shared.sockets.lock().insert(id, fd);
    id
}

// ---------------------------------------------------------------------------
// WSAStartup / WSACleanup
// ---------------------------------------------------------------------------

/// `int WSAStartup(WORD wVersionRequested, LPWSADATA lpWSAData)`
fn ws2_startup(ctx: &mut ExecutionContext, _teb_va: usize) -> (NtStatus, bool) {
    let args = NtSyscallArgs::from_ctx(ctx);
    let version_requested = args.arg0 as u16;
    let wsadata_ptr = args.arg1;

    if wsadata_ptr != 0 {
        // WSADATA layout (64-bit): wVersion @ 0, wHighVersion @ 2.
        // Rest (description, system status, max sockets) can be zero.
        unsafe {
            core::ptr::write(wsadata_ptr as *mut u16, version_requested);
            core::ptr::write((wsadata_ptr + 2) as *mut u16, 0x0202); // 2.2
        }
    }

    // WSAStartup returns 0 on success (not SOCKET_ERROR).
    ctx.regs.rax = 0;
    (NtStatus::STATUS_SUCCESS, false)
}

/// `int WSACleanup(void)` — always succeeds.
fn ws2_cleanup(ctx: &mut ExecutionContext, teb_va: usize) -> (NtStatus, bool) {
    wsa_ok(ctx, teb_va, 0)
}

// ---------------------------------------------------------------------------
// Socket lifecycle
// ---------------------------------------------------------------------------

/// `SOCKET socket(int af, int type, int protocol)`
fn ws2_socket(
    shared: &NtSharedState,
    ctx: &mut ExecutionContext,
    teb_va: usize,
) -> (NtStatus, bool) {
    let args = NtSyscallArgs::from_ctx(ctx);
    let af = args.arg0 as i32;
    let sock_type = args.arg1 as i32;

    let Some(net_arc) = shared.net.get() else {
        return wsa_fail(ctx, teb_va, WSANOTINITIALISED);
    };

    // AF_INET = 2, AF_INET6 = 23
    if af != 2 && af != 23 {
        return wsa_fail(ctx, teb_va, WSAEAFNOSUPPORT);
    }

    // SOCK_STREAM = 1, SOCK_DGRAM = 2
    let protocol = match sock_type {
        1 => litebox::net::Protocol::Tcp,
        2 => litebox::net::Protocol::Udp,
        _ => return wsa_fail(ctx, teb_va, WSAEAFNOSUPPORT),
    };

    let socket_fd = {
        let mut net = net_arc.lock();
        match net.socket(protocol) {
            Ok(fd) => fd,
            Err(_) => return wsa_fail(ctx, teb_va, WSAEMFILE),
        }
    };

    let sock_id = insert_socket(shared, socket_fd);
    let handle = {
        let mut handles = shared.handles.lock();
        handles.insert(crate::handle_table::NtObject::Socket { sock_id })
    };

    wsa_ok(ctx, teb_va, handle as usize)
}

/// `int closesocket(SOCKET s)`
fn ws2_closesocket(
    shared: &NtSharedState,
    ctx: &mut ExecutionContext,
    teb_va: usize,
) -> (NtStatus, bool) {
    let args = NtSyscallArgs::from_ctx(ctx);
    let sock = args.arg0 as u32;

    // Remove from handle table and get socket ID.
    let sock_id = {
        let mut handles = shared.handles.lock();
        match handles.close(sock) {
            Some(crate::handle_table::NtObject::Socket { sock_id }) => sock_id,
            _ => return wsa_fail(ctx, teb_va, WSAENOTSOCK),
        }
    };

    // Remove from socket table — this also provides the SocketFd for close().
    let Some(socket_fd) = shared.sockets.lock().remove(&sock_id) else {
        return wsa_fail(ctx, teb_va, WSAENOTSOCK);
    };

    if let Some(net_arc) = shared.net.get() {
        let mut net = net_arc.lock();
        let _ = net.close(&socket_fd, litebox::net::CloseBehavior::Immediate);
    }

    wsa_ok(ctx, teb_va, 0)
}

/// `int shutdown(SOCKET s, int how)`
fn ws2_shutdown(
    shared: &NtSharedState,
    ctx: &mut ExecutionContext,
    teb_va: usize,
) -> (NtStatus, bool) {
    let args = NtSyscallArgs::from_ctx(ctx);
    let sock = args.arg0 as u32;
    let how = args.arg1 as i32;

    let Some(sock_id) = sock_id_for_handle(shared, sock) else {
        return wsa_fail(ctx, teb_va, WSAENOTSOCK);
    };

    let Some(net_arc) = shared.net.get() else {
        return wsa_fail(ctx, teb_va, WSANOTINITIALISED);
    };

    // SD_RECEIVE=0, SD_SEND=1, SD_BOTH=2
    let (read, write) = match how {
        0 => (true, false),
        1 => (false, true),
        2 => (true, true),
        _ => return wsa_fail(ctx, teb_va, WSAEINVAL),
    };

    let sockets = shared.sockets.lock();
    let Some(socket_fd) = sockets.get(&sock_id) else {
        return wsa_fail(ctx, teb_va, WSAENOTSOCK);
    };
    let mut net = net_arc.lock();
    match net.shutdown(socket_fd, read, write) {
        Ok(()) => wsa_ok(ctx, teb_va, 0),
        Err(_) => wsa_fail(ctx, teb_va, WSAENOTCONN),
    }
}

// ---------------------------------------------------------------------------
// Connection
// ---------------------------------------------------------------------------

/// Parse a `sockaddr_in` or `sockaddr_in6` from guest memory.
fn parse_sockaddr(addr_ptr: usize, addr_len: i32) -> Option<core::net::SocketAddr> {
    if addr_ptr == 0 || addr_len < 4 {
        return None;
    }
    // Safety: guest memory is directly accessible in userland platforms.
    let family = unsafe { core::ptr::read(addr_ptr as *const u16) };
    match family {
        2 if addr_len >= 16 => {
            // AF_INET: sockaddr_in
            let port = u16::from_be(unsafe { core::ptr::read((addr_ptr + 2) as *const u16) });
            let ip_bytes: [u8; 4] = unsafe { core::ptr::read((addr_ptr + 4) as *const [u8; 4]) };
            let ip = core::net::Ipv4Addr::from(ip_bytes);
            Some(core::net::SocketAddr::V4(core::net::SocketAddrV4::new(
                ip, port,
            )))
        }
        23 if addr_len >= 28 => {
            // AF_INET6: sockaddr_in6
            let port = u16::from_be(unsafe { core::ptr::read((addr_ptr + 2) as *const u16) });
            let ip_bytes: [u8; 16] = unsafe { core::ptr::read((addr_ptr + 8) as *const [u8; 16]) };
            let ip = core::net::Ipv6Addr::from(ip_bytes);
            Some(core::net::SocketAddr::V6(core::net::SocketAddrV6::new(
                ip, port, 0, 0,
            )))
        }
        _ => None,
    }
}

/// Write a `SocketAddr` into guest `sockaddr_in`/`sockaddr_in6` buffer.
fn write_sockaddr(addr: &core::net::SocketAddr, buf_ptr: usize, len_ptr: usize) {
    // Safety: guest memory is directly accessible in userland platforms.
    match addr {
        core::net::SocketAddr::V4(v4) => {
            if buf_ptr != 0 {
                unsafe {
                    core::ptr::write(buf_ptr as *mut u16, 2); // AF_INET
                    core::ptr::write((buf_ptr + 2) as *mut u16, v4.port().to_be());
                    core::ptr::write((buf_ptr + 4) as *mut [u8; 4], v4.ip().octets());
                    core::ptr::write_bytes((buf_ptr + 8) as *mut u8, 0, 8); // sin_zero
                }
            }
            if len_ptr != 0 {
                unsafe { core::ptr::write(len_ptr as *mut i32, 16) };
            }
        }
        core::net::SocketAddr::V6(v6) => {
            if buf_ptr != 0 {
                unsafe {
                    core::ptr::write(buf_ptr as *mut u16, 23); // AF_INET6
                    core::ptr::write((buf_ptr + 2) as *mut u16, v6.port().to_be());
                    core::ptr::write((buf_ptr + 4) as *mut u32, 0); // flowinfo
                    core::ptr::write((buf_ptr + 8) as *mut [u8; 16], v6.ip().octets());
                    core::ptr::write((buf_ptr + 24) as *mut u32, 0); // scope_id
                }
            }
            if len_ptr != 0 {
                unsafe { core::ptr::write(len_ptr as *mut i32, 28) };
            }
        }
    }
}

/// `int connect(SOCKET s, const sockaddr* name, int namelen)`
fn ws2_connect(
    shared: &NtSharedState,
    ctx: &mut ExecutionContext,
    teb_va: usize,
) -> (NtStatus, bool) {
    let args = NtSyscallArgs::from_ctx(ctx);
    let sock = args.arg0 as u32;
    let addr_ptr = args.arg1;
    let addr_len = args.arg2 as i32;

    let Some(sock_id) = sock_id_for_handle(shared, sock) else {
        return wsa_fail(ctx, teb_va, WSAENOTSOCK);
    };

    let Some(addr) = parse_sockaddr(addr_ptr, addr_len) else {
        return wsa_fail(ctx, teb_va, WSAEINVAL);
    };

    let Some(net_arc) = shared.net.get() else {
        return wsa_fail(ctx, teb_va, WSANOTINITIALISED);
    };

    // Blocking connect: loop until connected or failed.
    let mut check_progress = false;
    loop {
        let result = {
            let sockets = shared.sockets.lock();
            let Some(socket_fd) = sockets.get(&sock_id) else {
                return wsa_fail(ctx, teb_va, WSAENOTSOCK);
            };
            let mut net = net_arc.lock();
            net.connect(socket_fd, &addr, check_progress)
        };
        match result {
            Ok(()) => return wsa_ok(ctx, teb_va, 0),
            Err(litebox::net::errors::ConnectError::InProgress) => {
                check_progress = true;
                {
                    for _ in 0..1_000 {
                        core::hint::spin_loop();
                    }
                };
            }
            Err(litebox::net::errors::ConnectError::TimedOut) => {
                return wsa_fail(ctx, teb_va, WSAETIMEDOUT);
            }
            Err(litebox::net::errors::ConnectError::UnsupportedAddress(_)) => {
                return wsa_fail(ctx, teb_va, WSAEAFNOSUPPORT);
            }
            Err(litebox::net::errors::ConnectError::Unaddressable) => {
                return wsa_fail(ctx, teb_va, WSAENETUNREACH);
            }
            Err(_) => return wsa_fail(ctx, teb_va, WSAECONNREFUSED),
        }
    }
}

// ---------------------------------------------------------------------------
// Data transfer
// ---------------------------------------------------------------------------

/// `int send(SOCKET s, const char* buf, int len, int flags)`
fn ws2_send(shared: &NtSharedState, ctx: &mut ExecutionContext, teb_va: usize) -> (NtStatus, bool) {
    let args = NtSyscallArgs::from_ctx(ctx);
    let sock = args.arg0 as u32;
    let buf_ptr = args.arg1;
    let len = args.arg2 as usize;

    let Some(sock_id) = sock_id_for_handle(shared, sock) else {
        return wsa_fail(ctx, teb_va, WSAENOTSOCK);
    };

    let Some(net_arc) = shared.net.get() else {
        return wsa_fail(ctx, teb_va, WSANOTINITIALISED);
    };

    // Safety: guest memory is directly accessible.
    let buf = unsafe { core::slice::from_raw_parts(buf_ptr as *const u8, len) };

    // Blocking send: retry on BufferFull.
    loop {
        let result = {
            let sockets = shared.sockets.lock();
            let Some(socket_fd) = sockets.get(&sock_id) else {
                return wsa_fail(ctx, teb_va, WSAENOTSOCK);
            };
            let mut net = net_arc.lock();
            net.send(socket_fd, buf, litebox::net::SendFlags::empty(), None)
        };
        match result {
            Ok(n) => return wsa_ok(ctx, teb_va, n),
            Err(litebox::net::errors::SendError::BufferFull) => {
                {
                    for _ in 0..1_000 {
                        core::hint::spin_loop();
                    }
                };
            }
            Err(litebox::net::errors::SendError::SocketInInvalidState) => {
                return wsa_fail(ctx, teb_va, WSAENOTCONN);
            }
            Err(_) => return wsa_fail(ctx, teb_va, WSAENOTCONN),
        }
    }
}

/// `int recv(SOCKET s, char* buf, int len, int flags)`
fn ws2_recv(shared: &NtSharedState, ctx: &mut ExecutionContext, teb_va: usize) -> (NtStatus, bool) {
    let args = NtSyscallArgs::from_ctx(ctx);
    let sock = args.arg0 as u32;
    let buf_ptr = args.arg1;
    let len = args.arg2 as usize;

    let Some(sock_id) = sock_id_for_handle(shared, sock) else {
        return wsa_fail(ctx, teb_va, WSAENOTSOCK);
    };

    let Some(net_arc) = shared.net.get() else {
        return wsa_fail(ctx, teb_va, WSANOTINITIALISED);
    };

    // Safety: guest memory is directly accessible.
    let buf = unsafe { core::slice::from_raw_parts_mut(buf_ptr as *mut u8, len) };

    // Blocking recv: retry while no data and socket is still open.
    loop {
        let result = {
            let sockets = shared.sockets.lock();
            let Some(socket_fd) = sockets.get(&sock_id) else {
                return wsa_fail(ctx, teb_va, WSAENOTSOCK);
            };
            let mut net = net_arc.lock();
            net.receive(socket_fd, buf, litebox::net::ReceiveFlags::empty(), None)
        };
        match result {
            Ok(n) if n > 0 => return wsa_ok(ctx, teb_va, n),
            Ok(_) => {
                // 0 bytes — socket open but no data yet; retry.
                {
                    for _ in 0..1_000 {
                        core::hint::spin_loop();
                    }
                };
            }
            Err(litebox::net::errors::ReceiveError::OperationFinished) => {
                // TCP FIN received — graceful close → return 0.
                return wsa_ok(ctx, teb_va, 0);
            }
            Err(litebox::net::errors::ReceiveError::SocketInInvalidState) => {
                return wsa_fail(ctx, teb_va, WSAECONNRESET);
            }
            Err(_) => return wsa_fail(ctx, teb_va, WSAENOTCONN),
        }
    }
}

/// `int sendto(SOCKET s, const char* buf, int len, int flags,
///             const sockaddr* to, int tolen)`
fn ws2_sendto(
    shared: &NtSharedState,
    ctx: &mut ExecutionContext,
    teb_va: usize,
) -> (NtStatus, bool) {
    let args = NtSyscallArgs::from_ctx(ctx);
    let sock = args.arg0 as u32;
    let buf_ptr = args.arg1;
    let len = args.arg2 as usize;
    let to_ptr = unsafe { NtSyscallArgs::arg4(ctx) };
    let to_len = unsafe { NtSyscallArgs::arg5(ctx) } as i32;

    let Some(sock_id) = sock_id_for_handle(shared, sock) else {
        return wsa_fail(ctx, teb_va, WSAENOTSOCK);
    };

    let Some(net_arc) = shared.net.get() else {
        return wsa_fail(ctx, teb_va, WSANOTINITIALISED);
    };

    let dest = if to_ptr != 0 && to_len > 0 {
        parse_sockaddr(to_ptr, to_len)
    } else {
        None
    };

    let buf = unsafe { core::slice::from_raw_parts(buf_ptr as *const u8, len) };

    loop {
        let result = {
            let sockets = shared.sockets.lock();
            let Some(socket_fd) = sockets.get(&sock_id) else {
                return wsa_fail(ctx, teb_va, WSAENOTSOCK);
            };
            let mut net = net_arc.lock();
            net.send(socket_fd, buf, litebox::net::SendFlags::empty(), dest)
        };
        match result {
            Ok(n) => return wsa_ok(ctx, teb_va, n),
            Err(litebox::net::errors::SendError::BufferFull) => {
                {
                    for _ in 0..1_000 {
                        core::hint::spin_loop();
                    }
                };
            }
            Err(_) => return wsa_fail(ctx, teb_va, WSAENOTCONN),
        }
    }
}

/// `int recvfrom(SOCKET s, char* buf, int len, int flags,
///               sockaddr* from, int* fromlen)`
fn ws2_recvfrom(
    shared: &NtSharedState,
    ctx: &mut ExecutionContext,
    teb_va: usize,
) -> (NtStatus, bool) {
    let args = NtSyscallArgs::from_ctx(ctx);
    let sock = args.arg0 as u32;
    let buf_ptr = args.arg1;
    let len = args.arg2 as usize;
    let from_ptr = unsafe { NtSyscallArgs::arg4(ctx) };
    let fromlen_ptr = unsafe { NtSyscallArgs::arg5(ctx) };

    let Some(sock_id) = sock_id_for_handle(shared, sock) else {
        return wsa_fail(ctx, teb_va, WSAENOTSOCK);
    };

    let Some(net_arc) = shared.net.get() else {
        return wsa_fail(ctx, teb_va, WSANOTINITIALISED);
    };

    let buf = unsafe { core::slice::from_raw_parts_mut(buf_ptr as *mut u8, len) };

    loop {
        let mut source: Option<core::net::SocketAddr> = None;
        let source_ref = if from_ptr != 0 {
            Some(&mut source)
        } else {
            None
        };
        let result = {
            let sockets = shared.sockets.lock();
            let Some(socket_fd) = sockets.get(&sock_id) else {
                return wsa_fail(ctx, teb_va, WSAENOTSOCK);
            };
            let mut net = net_arc.lock();
            net.receive(
                socket_fd,
                buf,
                litebox::net::ReceiveFlags::empty(),
                source_ref,
            )
        };
        match result {
            Ok(n) if n > 0 => {
                if from_ptr != 0
                    && let Some(ref addr) = source
                {
                    write_sockaddr(addr, from_ptr, fromlen_ptr);
                }
                return wsa_ok(ctx, teb_va, n);
            }
            Ok(_) => {
                {
                    for _ in 0..1_000 {
                        core::hint::spin_loop();
                    }
                };
            }
            Err(litebox::net::errors::ReceiveError::OperationFinished) => {
                return wsa_ok(ctx, teb_va, 0);
            }
            Err(_) => return wsa_fail(ctx, teb_va, WSAENOTCONN),
        }
    }
}

// ---------------------------------------------------------------------------
// Bind / Listen / Accept
// ---------------------------------------------------------------------------

/// `int bind(SOCKET s, const sockaddr* name, int namelen)`
fn ws2_bind(shared: &NtSharedState, ctx: &mut ExecutionContext, teb_va: usize) -> (NtStatus, bool) {
    let args = NtSyscallArgs::from_ctx(ctx);
    let sock = args.arg0 as u32;
    let addr_ptr = args.arg1;
    let addr_len = args.arg2 as i32;

    let Some(sock_id) = sock_id_for_handle(shared, sock) else {
        return wsa_fail(ctx, teb_va, WSAENOTSOCK);
    };

    let Some(addr) = parse_sockaddr(addr_ptr, addr_len) else {
        return wsa_fail(ctx, teb_va, WSAEINVAL);
    };

    let Some(net_arc) = shared.net.get() else {
        return wsa_fail(ctx, teb_va, WSANOTINITIALISED);
    };

    let sockets = shared.sockets.lock();
    let Some(socket_fd) = sockets.get(&sock_id) else {
        return wsa_fail(ctx, teb_va, WSAENOTSOCK);
    };
    let mut net = net_arc.lock();
    match net.bind(socket_fd, &addr) {
        Ok(()) => wsa_ok(ctx, teb_va, 0),
        Err(litebox::net::errors::BindError::PortAlreadyInUse(_)) => {
            wsa_fail(ctx, teb_va, WSAEADDRINUSE)
        }
        Err(litebox::net::errors::BindError::UnsupportedAddress(_)) => {
            wsa_fail(ctx, teb_va, WSAEADDRNOTAVAIL)
        }
        Err(_) => wsa_fail(ctx, teb_va, WSAEINVAL),
    }
}

/// `int listen(SOCKET s, int backlog)`
fn ws2_listen(
    shared: &NtSharedState,
    ctx: &mut ExecutionContext,
    teb_va: usize,
) -> (NtStatus, bool) {
    let args = NtSyscallArgs::from_ctx(ctx);
    let sock = args.arg0 as u32;
    let backlog = args.arg1 as u16;

    let Some(sock_id) = sock_id_for_handle(shared, sock) else {
        return wsa_fail(ctx, teb_va, WSAENOTSOCK);
    };

    let Some(net_arc) = shared.net.get() else {
        return wsa_fail(ctx, teb_va, WSANOTINITIALISED);
    };

    let sockets = shared.sockets.lock();
    let Some(socket_fd) = sockets.get(&sock_id) else {
        return wsa_fail(ctx, teb_va, WSAENOTSOCK);
    };
    let mut net = net_arc.lock();
    match net.listen(socket_fd, backlog.max(1)) {
        Ok(()) => wsa_ok(ctx, teb_va, 0),
        Err(_) => wsa_fail(ctx, teb_va, WSAEINVAL),
    }
}

/// `SOCKET accept(SOCKET s, sockaddr* addr, int* addrlen)`
fn ws2_accept(
    shared: &NtSharedState,
    ctx: &mut ExecutionContext,
    teb_va: usize,
) -> (NtStatus, bool) {
    let args = NtSyscallArgs::from_ctx(ctx);
    let sock = args.arg0 as u32;
    let addr_ptr = args.arg1;
    let addrlen_ptr = args.arg2;

    let Some(sock_id) = sock_id_for_handle(shared, sock) else {
        set_last_wsa_error(teb_va, WSAENOTSOCK);
        ctx.regs.rax = INVALID_SOCKET;
        return (NtStatus::STATUS_SUCCESS, false);
    };

    let Some(net_arc) = shared.net.get() else {
        set_last_wsa_error(teb_va, WSANOTINITIALISED);
        ctx.regs.rax = INVALID_SOCKET;
        return (NtStatus::STATUS_SUCCESS, false);
    };

    // Blocking accept.
    loop {
        let mut peer_addr = core::net::SocketAddr::V4(core::net::SocketAddrV4::new(
            core::net::Ipv4Addr::UNSPECIFIED,
            0,
        ));
        let peer_ref = if addr_ptr != 0 {
            Some(&mut peer_addr)
        } else {
            None
        };
        let result = {
            let sockets = shared.sockets.lock();
            let Some(socket_fd) = sockets.get(&sock_id) else {
                set_last_wsa_error(teb_va, WSAENOTSOCK);
                ctx.regs.rax = INVALID_SOCKET;
                return (NtStatus::STATUS_SUCCESS, false);
            };
            let mut net = net_arc.lock();
            net.accept(socket_fd, peer_ref)
        };
        match result {
            Ok(new_fd) => {
                if addr_ptr != 0 {
                    write_sockaddr(&peer_addr, addr_ptr, addrlen_ptr);
                }
                let new_sock_id = insert_socket(shared, new_fd);
                let handle = {
                    let mut handles = shared.handles.lock();
                    handles.insert(crate::handle_table::NtObject::Socket {
                        sock_id: new_sock_id,
                    })
                };
                return wsa_ok(ctx, teb_va, handle as usize);
            }
            Err(litebox::net::errors::AcceptError::NoConnectionsReady) => {
                {
                    for _ in 0..1_000 {
                        core::hint::spin_loop();
                    }
                };
            }
            Err(_) => {
                set_last_wsa_error(teb_va, WSAEINVAL);
                ctx.regs.rax = INVALID_SOCKET;
                return (NtStatus::STATUS_SUCCESS, false);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Socket options & control
// ---------------------------------------------------------------------------

/// `int setsockopt(SOCKET s, int level, int optname, const char* optval, int optlen)`
///
/// Minimal implementation — accept common options silently.
fn ws2_setsockopt(
    shared: &NtSharedState,
    ctx: &mut ExecutionContext,
    teb_va: usize,
) -> (NtStatus, bool) {
    let args = NtSyscallArgs::from_ctx(ctx);
    let sock = args.arg0 as u32;
    let level = args.arg1 as i32;
    let optname = args.arg2 as i32;

    // Validate the socket exists.
    if sock_id_for_handle(shared, sock).is_none() {
        return wsa_fail(ctx, teb_va, WSAENOTSOCK);
    }

    #[cfg(debug_assertions)]
    {
        use litebox::platform::DebugLogProvider as _;
        let msg = alloc::format!(
            "NT shim: setsockopt(sock={sock}, level=0x{level:X}, opt=0x{optname:X})\n"
        );
        litebox_platform_multiplex::platform().debug_log_print(&msg);
    }
    let _ = (level, optname);

    wsa_ok(ctx, teb_va, 0)
}

/// `int getsockopt(SOCKET s, int level, int optname, char* optval, int* optlen)`
///
/// Stub: return common defaults.
fn ws2_getsockopt(ctx: &mut ExecutionContext, teb_va: usize) -> (NtStatus, bool) {
    let args = NtSyscallArgs::from_ctx(ctx);
    let optval = args.arg3;
    let optlen_ptr = unsafe { NtSyscallArgs::arg4(ctx) };

    // Return 0 (disabled) for most options.
    if optval != 0 && optlen_ptr != 0 {
        let len = unsafe { core::ptr::read(optlen_ptr as *const i32) };
        if len >= 4 {
            unsafe {
                core::ptr::write(optval as *mut i32, 0);
                core::ptr::write(optlen_ptr as *mut i32, 4);
            }
        }
    }
    wsa_ok(ctx, teb_va, 0)
}

/// `int ioctlsocket(SOCKET s, long cmd, u_long* argp)`
///
/// FIONBIO (0x8004667E) — accept silently (smoltcp has no blocking modes).
fn ws2_ioctlsocket(ctx: &mut ExecutionContext, teb_va: usize) -> (NtStatus, bool) {
    wsa_ok(ctx, teb_va, 0)
}

/// `int select(int nfds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds,
///             timeval* timeout)`
///
/// Stub: returns 0 (timeout) immediately. Real implementation needed for
/// select-based I/O multiplexing.
fn ws2_select(ctx: &mut ExecutionContext, teb_va: usize) -> (NtStatus, bool) {
    log_unimplemented!("select() — returning 0 (timeout)");
    wsa_ok(ctx, teb_va, 0)
}

// ---------------------------------------------------------------------------
// Address query
// ---------------------------------------------------------------------------

/// `int getsockname(SOCKET s, sockaddr* name, int* namelen)`
fn ws2_getsockname(
    shared: &NtSharedState,
    ctx: &mut ExecutionContext,
    teb_va: usize,
) -> (NtStatus, bool) {
    let args = NtSyscallArgs::from_ctx(ctx);
    let sock = args.arg0 as u32;
    let name_ptr = args.arg1;
    let namelen_ptr = args.arg2;

    let Some(sock_id) = sock_id_for_handle(shared, sock) else {
        return wsa_fail(ctx, teb_va, WSAENOTSOCK);
    };

    let Some(net_arc) = shared.net.get() else {
        return wsa_fail(ctx, teb_va, WSANOTINITIALISED);
    };

    let sockets = shared.sockets.lock();
    let Some(socket_fd) = sockets.get(&sock_id) else {
        return wsa_fail(ctx, teb_va, WSAENOTSOCK);
    };
    let net = net_arc.lock();
    match net.get_local_addr(socket_fd) {
        Ok(addr) => {
            write_sockaddr(&addr, name_ptr, namelen_ptr);
            wsa_ok(ctx, teb_va, 0)
        }
        Err(_) => wsa_fail(ctx, teb_va, WSAEINVAL),
    }
}

/// `int getpeername(SOCKET s, sockaddr* name, int* namelen)`
fn ws2_getpeername(
    shared: &NtSharedState,
    ctx: &mut ExecutionContext,
    teb_va: usize,
) -> (NtStatus, bool) {
    let args = NtSyscallArgs::from_ctx(ctx);
    let sock = args.arg0 as u32;
    let name_ptr = args.arg1;
    let namelen_ptr = args.arg2;

    let Some(sock_id) = sock_id_for_handle(shared, sock) else {
        return wsa_fail(ctx, teb_va, WSAENOTSOCK);
    };

    let Some(net_arc) = shared.net.get() else {
        return wsa_fail(ctx, teb_va, WSANOTINITIALISED);
    };

    let sockets = shared.sockets.lock();
    let Some(socket_fd) = sockets.get(&sock_id) else {
        return wsa_fail(ctx, teb_va, WSAENOTSOCK);
    };
    let net = net_arc.lock();
    match net.get_remote_addr(socket_fd) {
        Ok(addr) => {
            write_sockaddr(&addr, name_ptr, namelen_ptr);
            wsa_ok(ctx, teb_va, 0)
        }
        Err(_) => wsa_fail(ctx, teb_va, WSAENOTCONN),
    }
}

// ---------------------------------------------------------------------------
// DNS: getaddrinfo / freeaddrinfo
// ---------------------------------------------------------------------------

/// `int getaddrinfo(const char* node, const char* service,
///                  const addrinfo* hints, addrinfo** res)`
///
/// Minimal: parse numeric addresses and well-known service names.
/// Returns `WSAHOST_NOT_FOUND` for hostnames that can't be resolved locally.
fn ws2_getaddrinfo(
    shared: &NtSharedState,
    ctx: &mut ExecutionContext,
    teb_va: usize,
) -> (NtStatus, bool) {
    let args = NtSyscallArgs::from_ctx(ctx);
    let node_ptr = args.arg0;
    let service_ptr = args.arg1;
    let _hints_ptr = args.arg2;
    let res_ptr = args.arg3;

    // Read the node name (C string).
    let node = if node_ptr != 0 {
        let s = unsafe { read_cstr(node_ptr) };
        if s.is_empty() { None } else { Some(s) }
    } else {
        None
    };

    // Read the service name/port.
    let service = if service_ptr != 0 {
        let s = unsafe { read_cstr(service_ptr) };
        if s.is_empty() { None } else { Some(s) }
    } else {
        None
    };

    // Resolve port from service string.
    let port: u16 = service
        .as_deref()
        .and_then(|s| {
            s.parse::<u16>().ok().or(match s {
                "http" => Some(80),
                "https" => Some(443),
                "dns" => Some(53),
                _ => None,
            })
        })
        .unwrap_or(0);

    // Resolve address from node string.
    let ip: Option<core::net::IpAddr> = node.as_deref().and_then(|n| {
        if let Ok(ip) = n.parse::<core::net::IpAddr>() {
            return Some(ip);
        }
        if n.eq_ignore_ascii_case("localhost") {
            return Some(core::net::IpAddr::V4(core::net::Ipv4Addr::LOCALHOST));
        }
        None
    });

    let Some(ip) = ip else {
        if res_ptr != 0 {
            unsafe { core::ptr::write(res_ptr as *mut usize, 0) };
        }
        set_last_wsa_error(teb_va, WSAHOST_NOT_FOUND);
        ctx.regs.rax = WSAHOST_NOT_FOUND as usize; // EAI_NONAME
        return (NtStatus::STATUS_SUCCESS, false);
    };

    // Allocate a minimal addrinfo + sockaddr_in in guest memory.
    // addrinfo (64-bit): 48 bytes; sockaddr_in: 16 bytes → 64 bytes total.
    let block = shared.process_state.alloc_rw_bytes(64);
    if block == 0 {
        set_last_wsa_error(teb_va, WSAHOST_NOT_FOUND);
        ctx.regs.rax = WSAHOST_NOT_FOUND as usize;
        return (NtStatus::STATUS_SUCCESS, false);
    }

    let addrinfo_va = block;
    let sockaddr_va = block + 48;

    match ip {
        core::net::IpAddr::V4(v4) => {
            let addr = core::net::SocketAddr::V4(core::net::SocketAddrV4::new(v4, port));
            write_sockaddr(&addr, sockaddr_va, 0);
            // Safety: we just allocated this memory as RW.
            unsafe {
                core::ptr::write(addrinfo_va as *mut i32, 0); // ai_flags
                core::ptr::write((addrinfo_va + 4) as *mut i32, 2); // ai_family = AF_INET
                core::ptr::write((addrinfo_va + 8) as *mut i32, 1); // ai_socktype = SOCK_STREAM
                core::ptr::write((addrinfo_va + 0x0C) as *mut i32, 6); // ai_protocol = TCP
                core::ptr::write((addrinfo_va + 0x10) as *mut u64, 16); // ai_addrlen
                core::ptr::write((addrinfo_va + 0x18) as *mut u64, 0); // ai_canonname
                core::ptr::write((addrinfo_va + 0x20) as *mut u64, sockaddr_va as u64); // ai_addr
                core::ptr::write((addrinfo_va + 0x28) as *mut u64, 0); // ai_next
            }
        }
        core::net::IpAddr::V6(v6) => {
            let addr = core::net::SocketAddr::V6(core::net::SocketAddrV6::new(v6, port, 0, 0));
            write_sockaddr(&addr, sockaddr_va, 0);
            unsafe {
                core::ptr::write(addrinfo_va as *mut i32, 0);
                core::ptr::write((addrinfo_va + 4) as *mut i32, 23); // AF_INET6
                core::ptr::write((addrinfo_va + 8) as *mut i32, 1);
                core::ptr::write((addrinfo_va + 0x0C) as *mut i32, 6);
                core::ptr::write((addrinfo_va + 0x10) as *mut u64, 28);
                core::ptr::write((addrinfo_va + 0x18) as *mut u64, 0);
                core::ptr::write((addrinfo_va + 0x20) as *mut u64, sockaddr_va as u64);
                core::ptr::write((addrinfo_va + 0x28) as *mut u64, 0);
            }
        }
    }

    // Write result pointer.
    if res_ptr != 0 {
        unsafe { core::ptr::write(res_ptr as *mut u64, addrinfo_va as u64) };
    }

    // getaddrinfo returns 0 on success.
    ctx.regs.rax = 0;
    (NtStatus::STATUS_SUCCESS, false)
}

/// `void freeaddrinfo(addrinfo* ai)` — leak for now (small, short-lived).
fn ws2_freeaddrinfo(ctx: &mut ExecutionContext, _teb_va: usize) -> (NtStatus, bool) {
    // TODO: properly free the addrinfo allocation.
    ctx.regs.rax = 0;
    (NtStatus::STATUS_SUCCESS, false)
}

// ---------------------------------------------------------------------------
// inet_pton
// ---------------------------------------------------------------------------

/// `int inet_pton(int af, const char* src, void* dst)`
///
/// Returns 1 on success, 0 if invalid for the family, -1 on error.
fn ws2_inet_pton(ctx: &mut ExecutionContext, teb_va: usize) -> (NtStatus, bool) {
    let args = NtSyscallArgs::from_ctx(ctx);
    let af = args.arg0 as i32;
    let src_ptr = args.arg1;
    let dst_ptr = args.arg2;

    if src_ptr == 0 || dst_ptr == 0 {
        return wsa_fail(ctx, teb_va, WSAEINVAL);
    }

    let src = unsafe { read_cstr(src_ptr) };

    match af {
        2 => {
            // AF_INET
            if let Ok(ip) = src.parse::<core::net::Ipv4Addr>() {
                unsafe { core::ptr::write(dst_ptr as *mut [u8; 4], ip.octets()) };
                ctx.regs.rax = 1;
            } else {
                ctx.regs.rax = 0;
            }
        }
        23 => {
            // AF_INET6
            if let Ok(ip) = src.parse::<core::net::Ipv6Addr>() {
                unsafe { core::ptr::write(dst_ptr as *mut [u8; 16], ip.octets()) };
                ctx.regs.rax = 1;
            } else {
                ctx.regs.rax = 0;
            }
        }
        _ => {
            return wsa_fail(ctx, teb_va, WSAEAFNOSUPPORT);
        }
    }
    (NtStatus::STATUS_SUCCESS, false)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Read a NUL-terminated C string from guest memory.
///
/// # Safety
/// `ptr` must be a valid guest VA pointing to a C string.
unsafe fn read_cstr(ptr: usize) -> alloc::string::String {
    let mut bytes = alloc::vec::Vec::new();
    let mut p = ptr;
    loop {
        let b = unsafe { core::ptr::read(p as *const u8) };
        if b == 0 {
            break;
        }
        bytes.push(b);
        p += 1;
        if bytes.len() > 4096 {
            break; // safety limit
        }
    }
    alloc::string::String::from_utf8_lossy(&bytes).into_owned()
}
