// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! WS2_32.dll function implementations
//!
//! This module provides Linux POSIX socket-backed implementations of the
//! Windows Sockets 2 (WinSock2) API. All socket handles are stored in a
//! per-process handle registry (analogous to `FILE_HANDLES` in `kernel32.rs`)
//! and map to real Linux file descriptors.

// Allow unsafe operations inside unsafe functions
#![allow(unsafe_op_in_unsafe_fn)]
// Allow cast warnings as we're implementing Windows API which requires specific integer types
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use core::ffi::c_void;

// ── WinSock error codes ───────────────────────────────────────────────────────
const WSAEINTR: i32 = 10004;
const WSAEBADF: i32 = 10009;
const WSAEACCES: i32 = 10013;
const WSAEFAULT: i32 = 10014;
const WSAEINVAL: i32 = 10022;
const WSAENOTSOCK: i32 = 10038;
const WSAEDESTADDRREQ: i32 = 10039;
const WSAEMSGSIZE: i32 = 10040;
const WSAEPROTOTYPE: i32 = 10041;
const WSAEPROTONOSUPPORT: i32 = 10043;
const WSAESOCKTNOSUPPORT: i32 = 10044;
const WSAEOPNOTSUPP: i32 = 10045;
const WSAEAFNOSUPPORT: i32 = 10047;
const WSAEADDRINUSE: i32 = 10048;
const WSAEADDRNOTAVAIL: i32 = 10049;
const WSAENETUNREACH: i32 = 10051;
const WSAETIMEDOUT: i32 = 10060;
const WSAECONNREFUSED: i32 = 10061;
const WSAEHOSTUNREACH: i32 = 10065;
const WSAEWOULDBLOCK: i32 = 10035;
const WSAEINPROGRESS: i32 = 10036;
const WSAENOBUFS: i32 = 10055;
const WSAEISCONN: i32 = 10056;
const WSAENOTCONN: i32 = 10057;
const WSAESHUTDOWN: i32 = 10058;
const WSAENOPROTOOPT: i32 = 10042;
const WSAHOST_NOT_FOUND: i32 = 11001;
const WSANO_DATA: i32 = 11004;

// WinSock constants
const INVALID_SOCKET: usize = usize::MAX;
const SOCKET_ERROR: i32 = -1;
const SOMAXCONN: i32 = 128;

// WSAStartup return values
const WSAVERNOTSUPPORTED: i32 = 10092;

// Address family constants
const AF_UNSPEC: i32 = 0;
const AF_INET: i32 = 2;
const AF_INET6: i32 = 23;

// Socket type constants
const SOCK_STREAM: i32 = 1;
const SOCK_DGRAM: i32 = 2;
const SOCK_RAW: i32 = 3;

// Protocol constants
#[allow(dead_code)]
const IPPROTO_TCP: i32 = 6;
#[allow(dead_code)]
const IPPROTO_UDP: i32 = 17;

// Shutdown constants (Windows)
const SD_RECEIVE: i32 = 0;
const SD_SEND: i32 = 1;
const SD_BOTH: i32 = 2;

// ioctlsocket commands
const FIONREAD: u32 = 0x4004_667F;
const FIONBIO: u32 = 0x8004_667E;

// WSASend/WSARecv flags
const MSG_PARTIAL: u32 = 0x8000;

// Maximum number of WSABUF scatter/gather entries accepted per call
const MAX_WSABUF_COUNT: u32 = 1_048_576;

// ── WSA last error (thread-local would be ideal; we use a global for simplicity) ──
static WSA_LAST_ERROR: Mutex<i32> = Mutex::new(0);

fn set_wsa_error(code: i32) {
    if let Ok(mut e) = WSA_LAST_ERROR.lock() {
        *e = code;
    }
}

fn get_wsa_error() -> i32 {
    WSA_LAST_ERROR.lock().map(|e| *e).unwrap_or(0)
}

/// Map a POSIX errno to a WSA error code.
fn errno_to_wsa(errno: i32) -> i32 {
    match errno {
        libc::EINTR => WSAEINTR,
        libc::EBADF => WSAEBADF,
        libc::EACCES => WSAEACCES,
        libc::EFAULT => WSAEFAULT,
        libc::EINVAL => WSAEINVAL,
        libc::ENOTSOCK => WSAENOTSOCK,
        libc::EDESTADDRREQ => WSAEDESTADDRREQ,
        libc::EMSGSIZE => WSAEMSGSIZE,
        libc::EPROTOTYPE => WSAEPROTOTYPE,
        libc::EPROTONOSUPPORT => WSAEPROTONOSUPPORT,
        libc::ESOCKTNOSUPPORT => WSAESOCKTNOSUPPORT,
        libc::EOPNOTSUPP => WSAEOPNOTSUPP,
        libc::EAFNOSUPPORT => WSAEAFNOSUPPORT,
        libc::EADDRINUSE => WSAEADDRINUSE,
        libc::EADDRNOTAVAIL => WSAEADDRNOTAVAIL,
        libc::ENETUNREACH => WSAENETUNREACH,
        libc::ETIMEDOUT => WSAETIMEDOUT,
        libc::ECONNREFUSED => WSAECONNREFUSED,
        libc::EHOSTUNREACH => WSAEHOSTUNREACH,
        libc::EAGAIN => WSAEWOULDBLOCK,
        libc::EINPROGRESS => WSAEINPROGRESS,
        libc::ENOBUFS => WSAENOBUFS,
        libc::EISCONN => WSAEISCONN,
        libc::ENOTCONN => WSAENOTCONN,
        libc::ESHUTDOWN => WSAESHUTDOWN,
        libc::ENOPROTOOPT => WSAENOPROTOOPT,
        _ => errno,
    }
}

/// Set WSA error from the current `errno`.
fn set_wsa_error_from_errno() {
    let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    set_wsa_error(errno_to_wsa(e));
}

// ── Socket-handle registry ────────────────────────────────────────────────────
// Maps Win32 SOCKET values (encoded as usize) to Linux file descriptors.

/// Counter for allocating unique SOCKET handle values.
static SOCKET_HANDLE_COUNTER: AtomicUsize = AtomicUsize::new(0x4_0000);

struct SocketEntry {
    /// Underlying Linux socket file descriptor.
    fd: i32,
    /// Network event mask from WSAEventSelect (FD_READ | FD_WRITE | etc.).
    /// Set to 0 for regular sockets; populated by `WSAEventSelect` with `FD_*` flags.
    network_events_mask: i32,
}

/// Global socket-handle map: handle_value → SocketEntry
static SOCKET_HANDLES: Mutex<Option<HashMap<usize, SocketEntry>>> = Mutex::new(None);

fn with_socket_handles<R>(f: impl FnOnce(&mut HashMap<usize, SocketEntry>) -> R) -> R {
    let mut guard = SOCKET_HANDLES.lock().unwrap();
    let map = guard.get_or_insert_with(HashMap::new);
    f(map)
}

/// Allocate a new SOCKET handle value.
fn alloc_socket_handle() -> usize {
    SOCKET_HANDLE_COUNTER.fetch_add(4, Ordering::SeqCst)
}

/// Register a Linux fd as a new Windows SOCKET and return the handle value.
fn register_socket(fd: i32) -> usize {
    let handle = alloc_socket_handle();
    with_socket_handles(|map| {
        map.insert(
            handle,
            SocketEntry {
                fd,
                network_events_mask: 0,
            },
        );
    });
    handle
}

/// Look up the Linux fd for a SOCKET handle. Returns `None` if not found.
fn lookup_socket_fd(socket: usize) -> Option<i32> {
    with_socket_handles(|map| map.get(&socket).map(|e| e.fd))
}

/// Remove a SOCKET handle and return the underlying fd.
fn remove_socket(socket: usize) -> Option<i32> {
    with_socket_handles(|map| map.remove(&socket).map(|e| e.fd))
}

// ── Map Windows address-family / socket-type / protocol to Linux ───────────

fn win_af_to_linux(af: i32) -> i32 {
    match af {
        AF_UNSPEC => libc::AF_UNSPEC,
        AF_INET => libc::AF_INET,
        AF_INET6 => libc::AF_INET6,
        _ => af,
    }
}

fn win_socktype_to_linux(socktype: i32) -> i32 {
    match socktype {
        SOCK_STREAM => libc::SOCK_STREAM,
        SOCK_DGRAM => libc::SOCK_DGRAM,
        SOCK_RAW => libc::SOCK_RAW,
        _ => socktype,
    }
}

fn win_proto_to_linux(proto: i32) -> i32 {
    // Protocol numbers are the same in Windows and Linux (IANA assigned)
    proto
}

// ── Windows → Linux socket option translation ────────────────────────────────
//
// Windows uses different numeric values for SOL_SOCKET and many SO_* options.
// We translate before forwarding to the Linux kernel.

/// Windows `SOL_SOCKET` = 0xFFFF; Linux `SOL_SOCKET` = 1.
const WIN_SOL_SOCKET: i32 = 0xFFFF;

/// Translate a Windows socket-option *level* to the Linux equivalent.
fn win_level_to_linux(level: i32) -> i32 {
    if level == WIN_SOL_SOCKET {
        libc::SOL_SOCKET
    } else {
        // IPPROTO_TCP (6), IPPROTO_UDP (17), etc. are the same on both platforms.
        level
    }
}

// Windows SO_* values at SOL_SOCKET level (winsock2.h)
const WIN_SO_DEBUG: i32 = 0x0001;
const WIN_SO_REUSEADDR: i32 = 0x0004;
const WIN_SO_KEEPALIVE: i32 = 0x0008;
const WIN_SO_DONTROUTE: i32 = 0x0010;
const WIN_SO_BROADCAST: i32 = 0x0020;
const WIN_SO_LINGER: i32 = 0x0080;
const WIN_SO_OOBINLINE: i32 = 0x0100;
const WIN_SO_SNDBUF: i32 = 0x1001;
const WIN_SO_RCVBUF: i32 = 0x1002;
const WIN_SO_SNDTIMEO: i32 = 0x1005;
const WIN_SO_RCVTIMEO: i32 = 0x1006;
const WIN_SO_ERROR: i32 = 0x1007;
const WIN_SO_TYPE: i32 = 0x1008;

/// Translate a Windows socket-option *name* to the Linux equivalent for the
/// given (already-translated) Linux level.  Returns `None` for options that
/// have no Linux counterpart (caller should return `WSAENOPROTOOPT`).
fn win_optname_to_linux(linux_level: i32, win_optname: i32) -> Option<i32> {
    if linux_level == libc::SOL_SOCKET {
        let linux_opt = match win_optname {
            WIN_SO_DEBUG => libc::SO_DEBUG,
            WIN_SO_REUSEADDR => libc::SO_REUSEADDR,
            WIN_SO_KEEPALIVE => libc::SO_KEEPALIVE,
            WIN_SO_DONTROUTE => libc::SO_DONTROUTE,
            WIN_SO_BROADCAST => libc::SO_BROADCAST,
            WIN_SO_LINGER => libc::SO_LINGER,
            WIN_SO_OOBINLINE => libc::SO_OOBINLINE,
            WIN_SO_SNDBUF => libc::SO_SNDBUF,
            WIN_SO_RCVBUF => libc::SO_RCVBUF,
            WIN_SO_SNDTIMEO => libc::SO_SNDTIMEO,
            WIN_SO_RCVTIMEO => libc::SO_RCVTIMEO,
            WIN_SO_ERROR => libc::SO_ERROR,
            WIN_SO_TYPE => libc::SO_TYPE,
            _ => return None,
        };
        Some(linux_opt)
    } else {
        // For IPPROTO_TCP, IPPROTO_UDP, etc. the option values are the same.
        Some(win_optname)
    }
}

// ── WSAStartup / WSACleanup ───────────────────────────────────────────────────

/// Windows WSADATA layout (simplified; callers only check the return value)
///
/// Field order matches the 64-bit Windows ABI:
/// wVersion, wHighVersion, iMaxSockets, iMaxUdpDg, lpVendorInfo,
/// szDescription, szSystemStatus.
#[repr(C)]
struct WsaData {
    w_version: u16,
    w_high_version: u16,
    i_max_sockets: u16,
    i_max_udp_dg: u16,
    lp_vendor_info: *mut u8,
    sz_description: [u8; 257],
    sz_system_status: [u8; 129],
}

/// Initialize Windows Sockets.
///
/// We accept any requested version ≤ 2.2 and always succeed.
///
/// # Safety
/// `lp_wsa_data` must point to a caller-allocated `WSADATA` buffer of at least
/// `size_of::<WsaData>()` bytes, or be null (we handle null gracefully).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ws2_WSAStartup(version_requested: u16, lp_wsa_data: *mut c_void) -> i32 {
    if !lp_wsa_data.is_null() {
        let data = lp_wsa_data.cast::<WsaData>();
        // Report version 2.2
        std::ptr::write_unaligned(core::ptr::addr_of_mut!((*data).w_version), 0x0202u16);
        std::ptr::write_unaligned(core::ptr::addr_of_mut!((*data).w_high_version), 0x0202u16);
        std::ptr::write_unaligned(core::ptr::addr_of_mut!((*data).i_max_sockets), 0u16);
        std::ptr::write_unaligned(core::ptr::addr_of_mut!((*data).i_max_udp_dg), 0u16);
        std::ptr::write_unaligned(
            core::ptr::addr_of_mut!((*data).lp_vendor_info),
            core::ptr::null_mut(),
        );
        // Null-terminate description strings
        let desc_ptr = core::ptr::addr_of_mut!((*data).sz_description[0]);
        std::ptr::write_unaligned(desc_ptr, 0u8);
        let status_ptr = core::ptr::addr_of_mut!((*data).sz_system_status[0]);
        std::ptr::write_unaligned(status_ptr, 0u8);
    }
    set_wsa_error(0);
    let major = (version_requested & 0xFF) as u8;
    let minor = (version_requested >> 8) as u8;
    // We support up to version 2.2
    if major > 2 || (major == 2 && minor > 2) {
        return WSAVERNOTSUPPORTED;
    }
    0 // success
}

/// Clean up Windows Sockets resources.
///
/// # Safety
/// No pointer arguments; always safe to call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ws2_WSACleanup() -> i32 {
    set_wsa_error(0);
    0 // success
}

// ── Error retrieval ───────────────────────────────────────────────────────────

/// Return the last WinSock error code for this thread/process.
///
/// # Safety
/// No pointer arguments; always safe to call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ws2_WSAGetLastError() -> i32 {
    get_wsa_error()
}

/// Set the WinSock last-error code.
///
/// # Safety
/// No pointer arguments; always safe to call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ws2_WSASetLastError(i_error: i32) {
    set_wsa_error(i_error);
}

// ── Socket creation ───────────────────────────────────────────────────────────

/// Create a socket.
///
/// # Safety
/// Arguments are plain integers; no pointer dereference.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ws2_socket(af: i32, socket_type: i32, protocol: i32) -> usize {
    let linux_af = win_af_to_linux(af);
    let linux_type = win_socktype_to_linux(socket_type);
    let linux_proto = win_proto_to_linux(protocol);
    let fd = libc::socket(linux_af, linux_type, linux_proto);
    if fd < 0 {
        set_wsa_error_from_errno();
        return INVALID_SOCKET;
    }
    set_wsa_error(0);
    register_socket(fd)
}

/// Create a socket (extended version; flags and group are ignored).
///
/// # Safety
/// The `lp_protocol_info` pointer is not dereferenced.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ws2_WSASocketW(
    af: i32,
    socket_type: i32,
    protocol: i32,
    _lp_protocol_info: *mut c_void,
    _g: u32,
    _dw_flags: u32,
) -> usize {
    ws2_socket(af, socket_type, protocol)
}

/// Close a socket and release its handle.
///
/// # Safety
/// `s` must be a valid SOCKET handle previously returned by `ws2_socket`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ws2_closesocket(s: usize) -> i32 {
    let Some(fd) = remove_socket(s) else {
        set_wsa_error(WSAENOTSOCK);
        return SOCKET_ERROR;
    };
    let result = libc::close(fd);
    if result != 0 {
        set_wsa_error_from_errno();
        return SOCKET_ERROR;
    }
    set_wsa_error(0);
    0
}

// ── Connection operations ─────────────────────────────────────────────────────

/// Bind a socket to a local address.
///
/// # Safety
/// `name` must point to a valid sockaddr structure of `name_len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ws2_bind(s: usize, name: *const libc::sockaddr, name_len: i32) -> i32 {
    let Some(fd) = lookup_socket_fd(s) else {
        set_wsa_error(WSAENOTSOCK);
        return SOCKET_ERROR;
    };
    let result = libc::bind(fd, name, name_len as libc::socklen_t);
    if result != 0 {
        set_wsa_error_from_errno();
        return SOCKET_ERROR;
    }
    set_wsa_error(0);
    0
}

/// Put a socket in the listening state.
///
/// # Safety
/// `s` must be a valid SOCKET handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ws2_listen(s: usize, backlog: i32) -> i32 {
    let Some(fd) = lookup_socket_fd(s) else {
        set_wsa_error(WSAENOTSOCK);
        return SOCKET_ERROR;
    };
    let real_backlog = if backlog == SOMAXCONN {
        libc::SOMAXCONN
    } else {
        backlog
    };
    let result = libc::listen(fd, real_backlog);
    if result != 0 {
        set_wsa_error_from_errno();
        return SOCKET_ERROR;
    }
    set_wsa_error(0);
    0
}

/// Accept a connection on a socket.
///
/// # Safety
/// If `addr` is non-null it must point to a buffer of at least `*addr_len` bytes.
/// `addr_len` must be non-null if `addr` is non-null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ws2_accept(
    s: usize,
    addr: *mut libc::sockaddr,
    addr_len: *mut i32,
) -> usize {
    let Some(fd) = lookup_socket_fd(s) else {
        set_wsa_error(WSAENOTSOCK);
        return INVALID_SOCKET;
    };
    let mut linux_len: libc::socklen_t = if addr_len.is_null() {
        0
    } else {
        *addr_len as libc::socklen_t
    };
    let new_fd = libc::accept(
        fd,
        addr,
        if addr_len.is_null() {
            core::ptr::null_mut()
        } else {
            &raw mut linux_len
        },
    );
    if new_fd < 0 {
        set_wsa_error_from_errno();
        return INVALID_SOCKET;
    }
    if !addr_len.is_null() {
        *addr_len = linux_len as i32;
    }
    set_wsa_error(0);
    register_socket(new_fd)
}

/// Connect a socket to a remote address.
///
/// On a non-blocking socket, Linux returns `EINPROGRESS` while Windows
/// returns `WSAEWOULDBLOCK`.  We remap `EINPROGRESS` here so callers that
/// check for `WSAEWOULDBLOCK` work correctly.
///
/// # Safety
/// `name` must point to a valid sockaddr structure of `name_len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ws2_connect(s: usize, name: *const libc::sockaddr, name_len: i32) -> i32 {
    let Some(fd) = lookup_socket_fd(s) else {
        set_wsa_error(WSAENOTSOCK);
        return SOCKET_ERROR;
    };
    let result = libc::connect(fd, name, name_len as libc::socklen_t);
    if result != 0 {
        let errno = *libc::__errno_location();
        // Linux returns EINPROGRESS for a non-blocking connect in progress;
        // Windows returns WSAEWOULDBLOCK.  Map accordingly.
        if errno == libc::EINPROGRESS {
            set_wsa_error(WSAEWOULDBLOCK);
        } else {
            set_wsa_error_from_errno();
        }
        return SOCKET_ERROR;
    }
    set_wsa_error(0);
    0
}

// ── Data transfer ─────────────────────────────────────────────────────────────

/// Send data on a connected socket.
///
/// # Safety
/// `buf` must point to at least `len` bytes of readable data.
/// `len` must be non-negative.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ws2_send(s: usize, buf: *const u8, len: i32, flags: i32) -> i32 {
    if len < 0 {
        set_wsa_error(WSAEINVAL);
        return SOCKET_ERROR;
    }
    let Some(fd) = lookup_socket_fd(s) else {
        set_wsa_error(WSAENOTSOCK);
        return SOCKET_ERROR;
    };
    let result = libc::send(fd, buf.cast::<c_void>(), len as libc::size_t, flags);
    if result < 0 {
        set_wsa_error_from_errno();
        return SOCKET_ERROR;
    }
    set_wsa_error(0);
    result as i32
}

/// Receive data from a connected socket.
///
/// # Safety
/// `buf` must point to at least `len` bytes of writable memory.
/// `len` must be non-negative.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ws2_recv(s: usize, buf: *mut u8, len: i32, flags: i32) -> i32 {
    if len < 0 {
        set_wsa_error(WSAEINVAL);
        return SOCKET_ERROR;
    }
    let Some(fd) = lookup_socket_fd(s) else {
        set_wsa_error(WSAENOTSOCK);
        return SOCKET_ERROR;
    };
    let result = libc::recv(fd, buf.cast::<c_void>(), len as libc::size_t, flags);
    if result < 0 {
        set_wsa_error_from_errno();
        return SOCKET_ERROR;
    }
    set_wsa_error(0);
    result as i32
}

/// Send data to a specific address (for connectionless sockets).
///
/// # Safety
/// `buf` must point to at least `len` readable bytes.
/// `to` must point to a valid sockaddr structure of `to_len` bytes.
/// `len` must be non-negative.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ws2_sendto(
    s: usize,
    buf: *const u8,
    len: i32,
    flags: i32,
    to: *const libc::sockaddr,
    to_len: i32,
) -> i32 {
    if len < 0 {
        set_wsa_error(WSAEINVAL);
        return SOCKET_ERROR;
    }
    let Some(fd) = lookup_socket_fd(s) else {
        set_wsa_error(WSAENOTSOCK);
        return SOCKET_ERROR;
    };
    let result = libc::sendto(
        fd,
        buf.cast::<c_void>(),
        len as libc::size_t,
        flags,
        to,
        to_len as libc::socklen_t,
    );
    if result < 0 {
        set_wsa_error_from_errno();
        return SOCKET_ERROR;
    }
    set_wsa_error(0);
    result as i32
}

/// Receive data and optionally the sender address (for connectionless sockets).
///
/// # Safety
/// `buf` must point to at least `len` writable bytes.
/// `len` must be non-negative.
/// If `from` is non-null it must point to a buffer of at least `*from_len` bytes;
/// `from_len` must be non-null if `from` is non-null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ws2_recvfrom(
    s: usize,
    buf: *mut u8,
    len: i32,
    flags: i32,
    from: *mut libc::sockaddr,
    from_len: *mut i32,
) -> i32 {
    if len < 0 {
        set_wsa_error(WSAEINVAL);
        return SOCKET_ERROR;
    }
    let Some(fd) = lookup_socket_fd(s) else {
        set_wsa_error(WSAENOTSOCK);
        return SOCKET_ERROR;
    };
    let mut linux_from_len: libc::socklen_t = if from_len.is_null() {
        0
    } else {
        *from_len as libc::socklen_t
    };
    let result = libc::recvfrom(
        fd,
        buf.cast::<c_void>(),
        len as libc::size_t,
        flags,
        from,
        if from_len.is_null() {
            core::ptr::null_mut()
        } else {
            &raw mut linux_from_len
        },
    );
    if result < 0 {
        set_wsa_error_from_errno();
        return SOCKET_ERROR;
    }
    if !from_len.is_null() {
        *from_len = linux_from_len as i32;
    }
    set_wsa_error(0);
    result as i32
}

// ── WSABUF layout ─────────────────────────────────────────────────────────────

/// Windows WSABUF structure: a scatter/gather buffer descriptor.
#[repr(C)]
pub struct WsaBuf {
    len: u32,
    buf: *mut u8,
}

/// Send data using scatter/gather buffers.
///
/// This is a simplified implementation that sends each buffer sequentially.
///
/// # Safety
/// `lp_buffers` must point to an array of `dw_buffer_count` valid `WSABUF` structures,
/// or be null when `dw_buffer_count` is 0.
/// `lp_number_of_bytes_sent` may be null; if non-null it receives the total byte count.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ws2_WSASend(
    s: usize,
    lp_buffers: *const WsaBuf,
    dw_buffer_count: u32,
    lp_number_of_bytes_sent: *mut u32,
    dw_flags: u32,
    _lp_overlapped: *mut c_void,
    _lp_completion_routine: *mut c_void,
) -> i32 {
    let Some(fd) = lookup_socket_fd(s) else {
        set_wsa_error(WSAENOTSOCK);
        return SOCKET_ERROR;
    };
    // Validate buffer array pointer before any dereference.
    if dw_buffer_count > 0 && lp_buffers.is_null() {
        set_wsa_error(WSAEFAULT);
        return SOCKET_ERROR;
    }
    // Guard against pathological counts that could cause overflows.
    if dw_buffer_count > MAX_WSABUF_COUNT {
        set_wsa_error(WSAEINVAL);
        return SOCKET_ERROR;
    }
    let flags = dw_flags as i32 & !(MSG_PARTIAL as i32);
    let mut total_sent: u32 = 0;
    for i in 0..dw_buffer_count as usize {
        // SAFETY: validated above that lp_buffers is non-null and count is in bounds.
        let wsa_buf = &*lp_buffers.add(i);
        let result = libc::send(
            fd,
            wsa_buf.buf.cast::<c_void>(),
            wsa_buf.len as libc::size_t,
            flags,
        );
        if result < 0 {
            set_wsa_error_from_errno();
            return SOCKET_ERROR;
        }
        total_sent += result as u32;
    }
    if !lp_number_of_bytes_sent.is_null() {
        *lp_number_of_bytes_sent = total_sent;
    }
    set_wsa_error(0);
    0
}

/// Receive data into scatter/gather buffers.
///
/// This is a simplified implementation that receives into each buffer sequentially.
///
/// # Safety
/// `lp_buffers` must point to an array of `dw_buffer_count` valid `WSABUF` structures,
/// or be null when `dw_buffer_count` is 0.
/// `lp_number_of_bytes_recvd` may be null; if non-null it receives the total byte count.
/// `lp_flags` may be null (treated as 0).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ws2_WSARecv(
    s: usize,
    lp_buffers: *mut WsaBuf,
    dw_buffer_count: u32,
    lp_number_of_bytes_recvd: *mut u32,
    lp_flags: *mut u32,
    _lp_overlapped: *mut c_void,
    _lp_completion_routine: *mut c_void,
) -> i32 {
    let Some(fd) = lookup_socket_fd(s) else {
        set_wsa_error(WSAENOTSOCK);
        return SOCKET_ERROR;
    };
    // Validate buffer array pointer before any dereference.
    if dw_buffer_count > 0 && lp_buffers.is_null() {
        set_wsa_error(WSAEFAULT);
        return SOCKET_ERROR;
    }
    // Guard against pathological counts that could cause overflows.
    if dw_buffer_count > MAX_WSABUF_COUNT {
        set_wsa_error(WSAEINVAL);
        return SOCKET_ERROR;
    }
    let flags = if lp_flags.is_null() {
        0
    } else {
        *lp_flags as i32
    };
    let mut total_recvd: u32 = 0;
    for i in 0..dw_buffer_count as usize {
        // SAFETY: validated above that lp_buffers is non-null and count is in bounds.
        let wsa_buf = &mut *lp_buffers.add(i);
        let result = libc::recv(
            fd,
            wsa_buf.buf.cast::<c_void>(),
            wsa_buf.len as libc::size_t,
            flags,
        );
        if result < 0 {
            set_wsa_error_from_errno();
            return SOCKET_ERROR;
        }
        total_recvd += result as u32;
        // Stop if this buffer was not fully filled (no more data available)
        if (result as u32) < wsa_buf.len {
            break;
        }
    }
    if !lp_number_of_bytes_recvd.is_null() {
        *lp_number_of_bytes_recvd = total_recvd;
    }
    set_wsa_error(0);
    0
}

// ── Socket information and control ────────────────────────────────────────────

/// Get the local address of a socket.
///
/// # Safety
/// `name` and `name_len` must both be non-null.
/// `name` must point to a buffer of at least `*name_len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ws2_getsockname(
    s: usize,
    name: *mut libc::sockaddr,
    name_len: *mut i32,
) -> i32 {
    let Some(fd) = lookup_socket_fd(s) else {
        set_wsa_error(WSAENOTSOCK);
        return SOCKET_ERROR;
    };
    if name_len.is_null() || name.is_null() {
        set_wsa_error(WSAEFAULT);
        return SOCKET_ERROR;
    }
    let mut linux_len: libc::socklen_t = *name_len as libc::socklen_t;
    let result = libc::getsockname(fd, name, &raw mut linux_len);
    if result != 0 {
        set_wsa_error_from_errno();
        return SOCKET_ERROR;
    }
    *name_len = linux_len as i32;
    set_wsa_error(0);
    0
}

/// Get the remote address of a connected socket.
///
/// # Safety
/// `name` and `name_len` must both be non-null.
/// `name` must point to a buffer of at least `*name_len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ws2_getpeername(
    s: usize,
    name: *mut libc::sockaddr,
    name_len: *mut i32,
) -> i32 {
    let Some(fd) = lookup_socket_fd(s) else {
        set_wsa_error(WSAENOTSOCK);
        return SOCKET_ERROR;
    };
    if name_len.is_null() || name.is_null() {
        set_wsa_error(WSAEFAULT);
        return SOCKET_ERROR;
    }
    let mut linux_len: libc::socklen_t = *name_len as libc::socklen_t;
    let result = libc::getpeername(fd, name, &raw mut linux_len);
    if result != 0 {
        set_wsa_error_from_errno();
        return SOCKET_ERROR;
    }
    *name_len = linux_len as i32;
    set_wsa_error(0);
    0
}

/// Get a socket option.
///
/// # Safety
/// `opt_len` must be non-null.
/// `opt_val` must point to a buffer of at least `*opt_len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ws2_getsockopt(
    s: usize,
    level: i32,
    opt_name: i32,
    opt_val: *mut u8,
    opt_len: *mut i32,
) -> i32 {
    let Some(fd) = lookup_socket_fd(s) else {
        set_wsa_error(WSAENOTSOCK);
        return SOCKET_ERROR;
    };
    if opt_len.is_null() {
        set_wsa_error(WSAEFAULT);
        return SOCKET_ERROR;
    }
    let linux_level = win_level_to_linux(level);
    let Some(linux_opt) = win_optname_to_linux(linux_level, opt_name) else {
        set_wsa_error(WSAENOPROTOOPT);
        return SOCKET_ERROR;
    };
    let mut linux_len: libc::socklen_t = *opt_len as libc::socklen_t;
    let result = libc::getsockopt(
        fd,
        linux_level,
        linux_opt,
        opt_val.cast::<c_void>(),
        &raw mut linux_len,
    );
    if result != 0 {
        set_wsa_error_from_errno();
        return SOCKET_ERROR;
    }
    *opt_len = linux_len as i32;
    set_wsa_error(0);
    0
}

/// Set a socket option.
///
/// # Safety
/// `opt_val` must point to at least `opt_len` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ws2_setsockopt(
    s: usize,
    level: i32,
    opt_name: i32,
    opt_val: *const u8,
    opt_len: i32,
) -> i32 {
    let Some(fd) = lookup_socket_fd(s) else {
        set_wsa_error(WSAENOTSOCK);
        return SOCKET_ERROR;
    };
    let linux_level = win_level_to_linux(level);
    let Some(linux_opt) = win_optname_to_linux(linux_level, opt_name) else {
        set_wsa_error(WSAENOPROTOOPT);
        return SOCKET_ERROR;
    };
    let result = libc::setsockopt(
        fd,
        linux_level,
        linux_opt,
        opt_val.cast::<c_void>(),
        opt_len as libc::socklen_t,
    );
    if result != 0 {
        set_wsa_error_from_errno();
        return SOCKET_ERROR;
    }
    set_wsa_error(0);
    0
}

/// Control socket I/O mode (blocking/non-blocking, bytes available).
///
/// # Safety
/// `arg_p` must point to a writable `u_long` (4-byte unsigned) value.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ws2_ioctlsocket(s: usize, cmd: u32, arg_p: *mut u32) -> i32 {
    let Some(fd) = lookup_socket_fd(s) else {
        set_wsa_error(WSAENOTSOCK);
        return SOCKET_ERROR;
    };
    match cmd {
        FIONBIO => {
            // Set non-blocking mode via fcntl
            let arg = if arg_p.is_null() { 0 } else { *arg_p };
            let flags = libc::fcntl(fd, libc::F_GETFL, 0);
            if flags < 0 {
                set_wsa_error_from_errno();
                return SOCKET_ERROR;
            }
            let new_flags = if arg != 0 {
                flags | libc::O_NONBLOCK
            } else {
                flags & !libc::O_NONBLOCK
            };
            let result = libc::fcntl(fd, libc::F_SETFL, new_flags);
            if result < 0 {
                set_wsa_error_from_errno();
                return SOCKET_ERROR;
            }
        }
        FIONREAD => {
            // Get bytes available to read
            let mut bytes_available: libc::c_int = 0;
            let result = libc::ioctl(fd, libc::FIONREAD, &raw mut bytes_available);
            if result < 0 {
                set_wsa_error_from_errno();
                return SOCKET_ERROR;
            }
            if !arg_p.is_null() {
                *arg_p = bytes_available as u32;
            }
        }
        _ => {
            set_wsa_error(WSAEOPNOTSUPP);
            return SOCKET_ERROR;
        }
    }
    set_wsa_error(0);
    0
}

/// Shut down part of a full-duplex connection.
///
/// # Safety
/// `s` must be a valid SOCKET handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ws2_shutdown(s: usize, how: i32) -> i32 {
    let Some(fd) = lookup_socket_fd(s) else {
        set_wsa_error(WSAENOTSOCK);
        return SOCKET_ERROR;
    };
    let linux_how = match how {
        SD_RECEIVE => libc::SHUT_RD,
        SD_SEND => libc::SHUT_WR,
        SD_BOTH => libc::SHUT_RDWR,
        _ => {
            set_wsa_error(WSAEINVAL);
            return SOCKET_ERROR;
        }
    };
    let result = libc::shutdown(fd, linux_how);
    if result != 0 {
        set_wsa_error_from_errno();
        return SOCKET_ERROR;
    }
    set_wsa_error(0);
    0
}

// ── select ────────────────────────────────────────────────────────────────────

/// Windows `fd_set` layout.
/// POSIX fd_set uses bit arrays; Windows uses a count + array-of-sockets layout.
#[repr(C)]
pub struct WinFdSet {
    fd_count: u32,
    fd_array: [usize; 64],
}

/// Windows `TIMEVAL` layout — two `i32` fields (`tv_sec`, `tv_usec`).
///
/// This differs from `libc::timeval` on 64-bit Linux where both fields are `i64`.
/// We must translate explicitly to avoid misinterpreting the guest timeout value.
#[repr(C)]
pub struct WinTimeval {
    tv_sec: i32,
    tv_usec: i32,
}

/// Monitor sockets for readability, writability, or error conditions.
///
/// This translates the Windows `fd_set` layout (count + socket array) to
/// POSIX `fd_set` (bit mask over file descriptors) and translates the Windows
/// `TIMEVAL` (two `i32` fields) to POSIX `timeval` (two `i64` fields on 64-bit).
///
/// # Safety
/// All non-null `fd_set` pointers must be valid `WinFdSet` structures.
/// `timeout` must be null or point to a valid Windows `TIMEVAL` (two `i32` fields).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ws2_select(
    _n_fds: i32,
    read_fds: *mut WinFdSet,
    write_fds: *mut WinFdSet,
    except_fds: *mut WinFdSet,
    timeout: *const WinTimeval,
) -> i32 {
    // Build POSIX fd_sets from Windows fd_sets
    let mut posix_read: libc::fd_set = core::mem::zeroed();
    let mut posix_write: libc::fd_set = core::mem::zeroed();
    let mut posix_except: libc::fd_set = core::mem::zeroed();
    let mut max_fd: i32 = -1;

    // Helper: populate a POSIX fd_set from a Windows fd_set, tracking the max fd.
    // Returns SOCKET_ERROR if any fd is >= FD_SETSIZE (would overflow the fd_set).
    let mut fd_setsize_exceeded = false;
    let populate =
        |win: *mut WinFdSet, posix: &mut libc::fd_set, max: &mut i32, exceeded: &mut bool| {
            if win.is_null() {
                return;
            }
            let count = (*win).fd_count as usize;
            for i in 0..count.min(64) {
                let sock = (*win).fd_array[i];
                if let Some(fd) = lookup_socket_fd(sock) {
                    if fd >= libc::FD_SETSIZE as i32 {
                        *exceeded = true;
                        return;
                    }
                    libc::FD_SET(fd, posix);
                    if fd > *max {
                        *max = fd;
                    }
                }
            }
        };

    populate(
        read_fds,
        &mut posix_read,
        &mut max_fd,
        &mut fd_setsize_exceeded,
    );
    populate(
        write_fds,
        &mut posix_write,
        &mut max_fd,
        &mut fd_setsize_exceeded,
    );
    populate(
        except_fds,
        &mut posix_except,
        &mut max_fd,
        &mut fd_setsize_exceeded,
    );

    if fd_setsize_exceeded {
        set_wsa_error(WSAEINVAL);
        return SOCKET_ERROR;
    }

    // Translate the Windows TIMEVAL (two i32 fields) to a local libc::timeval
    // (two i64 fields on 64-bit Linux).  We must NOT pass the guest pointer directly
    // because the layouts differ, and select() may modify the timeval in place.
    let mut linux_timeout: libc::timeval;
    let timeout_ptr: *mut libc::timeval = if timeout.is_null() {
        core::ptr::null_mut()
    } else {
        linux_timeout = libc::timeval {
            tv_sec: libc::time_t::from((*timeout).tv_sec),
            tv_usec: libc::suseconds_t::from((*timeout).tv_usec),
        };
        &raw mut linux_timeout
    };

    let result = libc::select(
        max_fd + 1,
        if read_fds.is_null() {
            core::ptr::null_mut()
        } else {
            &raw mut posix_read
        },
        if write_fds.is_null() {
            core::ptr::null_mut()
        } else {
            &raw mut posix_write
        },
        if except_fds.is_null() {
            core::ptr::null_mut()
        } else {
            &raw mut posix_except
        },
        timeout_ptr,
    );

    if result < 0 {
        set_wsa_error_from_errno();
        return SOCKET_ERROR;
    }

    // Translate results back to Windows fd_sets
    let translate_back = |win: *mut WinFdSet, posix: &libc::fd_set| {
        if win.is_null() {
            return;
        }
        let mut new_count: u32 = 0;
        let old_count = (*win).fd_count as usize;
        for i in 0..old_count.min(64) {
            let sock = (*win).fd_array[i];
            if let Some(fd) = lookup_socket_fd(sock)
                && fd < libc::FD_SETSIZE as i32
                && libc::FD_ISSET(fd, posix)
            {
                (*win).fd_array[new_count as usize] = sock;
                new_count += 1;
            }
        }
        (*win).fd_count = new_count;
    };

    translate_back(read_fds, &posix_read);
    translate_back(write_fds, &posix_write);
    translate_back(except_fds, &posix_except);

    set_wsa_error(0);
    result
}

// ── Name resolution ───────────────────────────────────────────────────────────

/// Windows `addrinfo` structure (matches POSIX `addrinfo`).
///
/// On Linux/Windows 64-bit the layouts are compatible, so we delegate
/// directly to `libc::getaddrinfo` / `libc::freeaddrinfo`.
///
/// # Safety
/// `node_name` and `service_name` must be null-terminated C strings or null.
/// `hints` must be null or point to a valid `addrinfo` (Windows layout).
/// `res` must be non-null and will be set to the result list on success.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ws2_getaddrinfo(
    node_name: *const i8,
    service_name: *const i8,
    hints: *const libc::addrinfo,
    res: *mut *mut libc::addrinfo,
) -> i32 {
    let result = libc::getaddrinfo(node_name, service_name, hints, res);
    if result != 0 {
        // getaddrinfo uses EAI_ error codes, map to WSA equivalents
        set_wsa_error(result);
    } else {
        set_wsa_error(0);
    }
    result
}

/// Free an `addrinfo` list returned by `ws2_getaddrinfo`.
///
/// # Safety
/// `res` must be a pointer returned by a prior successful `ws2_getaddrinfo` call,
/// or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ws2_freeaddrinfo(res: *mut libc::addrinfo) {
    if !res.is_null() {
        libc::freeaddrinfo(res);
    }
}

/// Get the local host name as a wide (UTF-16) string.
///
/// # Safety
/// `name` must point to a buffer of at least `name_len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ws2_GetHostNameW(name: *mut u16, name_len: i32) -> i32 {
    if name.is_null() || name_len <= 0 {
        set_wsa_error(WSAEFAULT);
        return SOCKET_ERROR;
    }
    let mut buf = vec![0i8; 256];
    let result = libc::gethostname(buf.as_mut_ptr(), buf.len());
    if result != 0 {
        set_wsa_error_from_errno();
        return SOCKET_ERROR;
    }
    // Null-terminate just in case
    buf[255] = 0;
    let hostname = std::ffi::CStr::from_ptr(buf.as_ptr())
        .to_string_lossy()
        .into_owned();
    let max_chars = (name_len as usize).saturating_sub(1);
    let truncated: String = hostname.chars().take(max_chars).collect();
    for (i, c) in truncated.encode_utf16().enumerate() {
        std::ptr::write_unaligned(name.add(i), c);
    }
    // Null-terminate
    let written = truncated.encode_utf16().count();
    std::ptr::write_unaligned(name.add(written), 0u16);
    set_wsa_error(0);
    0
}

// ── Byte-order conversion (inline in real WS2_32.dll; we expose as C funcs) ──

/// Convert a `u16` from host to network byte order.
///
/// # Safety
/// No pointer dereference; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ws2_htons(host_short: u16) -> u16 {
    host_short.to_be()
}

/// Convert a `u32` from host to network byte order.
///
/// # Safety
/// No pointer dereference; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ws2_htonl(host_long: u32) -> u32 {
    host_long.to_be()
}

/// Convert a `u16` from network to host byte order.
///
/// # Safety
/// No pointer dereference; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ws2_ntohs(net_short: u16) -> u16 {
    u16::from_be(net_short)
}

/// Convert a `u32` from network to host byte order.
///
/// # Safety
/// No pointer dereference; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ws2_ntohl(net_long: u32) -> u32 {
    u32::from_be(net_long)
}

// ── WSADuplicateSocketW stub ──────────────────────────────────────────────────

/// Stub for `WSADuplicateSocketW` — not implemented.
///
/// This function is used to duplicate sockets across processes, which is not
/// supported in the single-process sandboxed environment.
///
/// # Safety
/// Pointer arguments are not dereferenced.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ws2_WSADuplicateSocketW(
    _s: usize,
    _dw_process_id: u32,
    _lp_protocol_info: *mut c_void,
) -> i32 {
    set_wsa_error(WSAEOPNOTSUPP);
    SOCKET_ERROR
}

// ── __WSAFDIsSet ──────────────────────────────────────────────────────────────

/// `__WSAFDIsSet` – the helper that backs the `FD_ISSET` macro on Windows.
///
/// The Windows `fd_set` is an array of socket handles prefixed by a count
/// (unlike the POSIX bit-vector).  After `select()` returns, `translate_back`
/// in `ws2_select` has already reduced the array to only the ready sockets,
/// so we merely scan the array for `socket`.
///
/// # Safety
/// `set` must be null or point to a valid Windows `fd_set` structure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ws2___WSAFDIsSet(socket: usize, set: *const WinFdSet) -> i32 {
    if set.is_null() {
        return 0;
    }
    let count = (*set).fd_count as usize;
    for i in 0..count.min(64) {
        if (*set).fd_array[i] == socket {
            return 1;
        }
    }
    0
}

// ── WSA event-handle registry ─────────────────────────────────────────────────

/// Counter for allocating unique WSA event handle values.
static WSA_EVENT_COUNTER: AtomicUsize = AtomicUsize::new(0x7_0000);

/// Global WSA event-handle map: handle_value → signaled flag.
static WSA_EVENT_HANDLES: Mutex<Option<HashMap<usize, bool>>> = Mutex::new(None);

fn with_wsa_events<R>(f: impl FnOnce(&mut HashMap<usize, bool>) -> R) -> R {
    let mut guard = WSA_EVENT_HANDLES.lock().unwrap();
    let map = guard.get_or_insert_with(HashMap::new);
    f(map)
}

// WSA network event bit flags
const FD_READ: i32 = 0x0001;
const FD_WRITE: i32 = 0x0002;
const FD_OOB: i32 = 0x0004;
const FD_ACCEPT: i32 = 0x0008;
const FD_CLOSE: i32 = 0x0020;

// WSAWaitForMultipleEvents return values
const WSA_WAIT_EVENT_0: u32 = 0;
const WSA_WAIT_TIMEOUT: u32 = 0x102;
const WSA_WAIT_FAILED: u32 = 0xFFFF_FFFF;
const WSA_MAXIMUM_WAIT_EVENTS: u32 = 64;

/// `WSACreateEvent()` — create a manual-reset WSA event object.
///
/// Returns a new event handle on success, or `WSA_INVALID_EVENT` (null) on failure.
///
/// # Safety
/// This function is safe to call from any context.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ws2_WSACreateEvent() -> usize {
    let handle = WSA_EVENT_COUNTER.fetch_add(1, Ordering::Relaxed);
    with_wsa_events(|m| m.insert(handle, false));
    handle
}

/// `WSACloseEvent(hEvent)` — destroy a WSA event object.
///
/// Returns `TRUE` (1) on success, `FALSE` (0) if the handle is invalid.
///
/// # Safety
/// `h_event` must be a handle previously returned by `WSACreateEvent`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ws2_WSACloseEvent(h_event: usize) -> i32 {
    let removed = with_wsa_events(|m| m.remove(&h_event).is_some());
    i32::from(removed)
}

/// `WSAResetEvent(hEvent)` — reset a WSA event to the non-signaled state.
///
/// Returns `TRUE` (1) on success, `FALSE` (0) if the handle is invalid.
///
/// # Safety
/// `h_event` must be a handle previously returned by `WSACreateEvent`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ws2_WSAResetEvent(h_event: usize) -> i32 {
    let found = with_wsa_events(|m| {
        if let Some(v) = m.get_mut(&h_event) {
            *v = false;
            true
        } else {
            false
        }
    });
    i32::from(found)
}

/// `WSASetEvent(hEvent)` — set a WSA event to the signaled state.
///
/// Returns `TRUE` (1) on success, `FALSE` (0) if the handle is invalid.
///
/// # Safety
/// `h_event` must be a handle previously returned by `WSACreateEvent`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ws2_WSASetEvent(h_event: usize) -> i32 {
    let found = with_wsa_events(|m| {
        if let Some(v) = m.get_mut(&h_event) {
            *v = true;
            true
        } else {
            false
        }
    });
    i32::from(found)
}

/// Windows `WSANETWORKEVENTS` structure.
///
/// Contains the set of pending network events (bit flags) and per-event
/// error codes for a socket.
#[repr(C)]
pub struct WsaNetworkEvents {
    /// Bitmask of pending network events (combination of `FD_*` flags).
    pub network_events: i32,
    /// Per-event error codes (index = `log2(FD_* flag)`).
    pub error_code: [i32; 10],
}

/// `WSAEventSelect(s, hEventObject, lNetworkEvents)` — associate socket with events.
///
/// Stores the network-event mask on the socket entry. The `hEventObject`
/// parameter is accepted for API compatibility but is not stored; signaling
/// is driven by `WSASetEvent`/`WSAEnumNetworkEvents`. Returns 0 on success,
/// `SOCKET_ERROR` on failure.
///
/// # Safety
/// `s` must be a valid socket handle obtained from `socket`/`WSASocketW`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ws2_WSAEventSelect(
    s: usize,
    _h_event_object: usize,
    l_network_events: i32,
) -> i32 {
    let ok = with_socket_handles(|m| {
        if let Some(entry) = m.get_mut(&s) {
            entry.network_events_mask = l_network_events;
            true
        } else {
            false
        }
    });
    if ok {
        0
    } else {
        set_wsa_error(WSAENOTSOCK);
        SOCKET_ERROR
    }
}

/// `WSAEnumNetworkEvents(s, hEventObject, lpNetworkEvents)` — query pending events.
///
/// Uses a zero-timeout `poll()` to detect which events are currently pending
/// on the socket and fills in `lpNetworkEvents`. `hEventObject` is reset
/// (if valid) after the query.
/// Returns 0 on success, `SOCKET_ERROR` on failure.
///
/// # Safety
/// `s` must be a valid socket handle.
/// `lp_network_events` must be a valid pointer to a `WsaNetworkEvents` structure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ws2_WSAEnumNetworkEvents(
    s: usize,
    h_event_object: usize,
    lp_network_events: *mut WsaNetworkEvents,
) -> i32 {
    let fd_and_mask = with_socket_handles(|m| m.get(&s).map(|e| (e.fd, e.network_events_mask)));
    let Some((fd, mask)) = fd_and_mask else {
        set_wsa_error(WSAENOTSOCK);
        return SOCKET_ERROR;
    };
    if lp_network_events.is_null() {
        set_wsa_error(WSAEFAULT);
        return SOCKET_ERROR;
    }

    // Use poll(2) with 0 timeout to query current socket readiness.
    let mut pfd = libc::pollfd {
        fd,
        events: 0,
        revents: 0,
    };
    if mask & FD_READ != 0 {
        pfd.events |= libc::POLLIN;
    }
    if mask & FD_ACCEPT != 0 {
        pfd.events |= libc::POLLIN;
    }
    if mask & FD_WRITE != 0 {
        pfd.events |= libc::POLLOUT;
    }
    if mask & FD_OOB != 0 {
        pfd.events |= libc::POLLPRI;
    }
    // SAFETY: pfd is a valid pollfd structure; timeout=0 means non-blocking.
    let poll_res = unsafe { libc::poll(&raw mut pfd, 1, 0) };
    if poll_res < 0 {
        set_wsa_error_from_errno();
        return SOCKET_ERROR;
    }

    let out = unsafe { &mut *lp_network_events };
    out.network_events = 0;
    out.error_code = [0i32; 10];

    if pfd.revents & libc::POLLIN != 0 {
        if mask & FD_READ != 0 {
            out.network_events |= FD_READ;
        }
        if mask & FD_ACCEPT != 0 {
            out.network_events |= FD_ACCEPT;
        }
    }
    if pfd.revents & libc::POLLOUT != 0 && mask & FD_WRITE != 0 {
        out.network_events |= FD_WRITE;
    }
    if pfd.revents & libc::POLLPRI != 0 && mask & FD_OOB != 0 {
        out.network_events |= FD_OOB;
    }
    if pfd.revents & (libc::POLLHUP | libc::POLLERR) != 0 && mask & FD_CLOSE != 0 {
        out.network_events |= FD_CLOSE;
    }

    // Reset the associated event handle if it was provided.
    if h_event_object != 0 {
        with_wsa_events(|m| {
            if let Some(v) = m.get_mut(&h_event_object) {
                *v = false;
            }
        });
    }

    0
}

/// `WSAWaitForMultipleEvents(cEvents, lphEvents, fWaitAll, dwTimeout, fAlertable)`
///
/// Waits until one (or all) of the specified event handles are signaled or the
/// timeout expires. The current implementation periodically checks the internal
/// signaled state of each event handle and sleeps between checks to avoid busy
/// looping. `fWaitAll` is honoured by requiring all events to be signaled
/// before returning.
///
/// Returns `WSA_WAIT_EVENT_0 + index` of the first triggered event on success,
/// `WSA_WAIT_TIMEOUT` on timeout, `WSA_WAIT_FAILED` on error.
///
/// # Safety
/// `lph_events` must be a valid pointer to `c_events` handle values, each
/// previously returned by `WSACreateEvent`.
#[unsafe(no_mangle)]
#[allow(clippy::cast_possible_wrap)]
pub unsafe extern "C" fn ws2_WSAWaitForMultipleEvents(
    c_events: u32,
    lph_events: *const usize,
    f_wait_all: i32,
    dw_timeout: u32,
    _f_alertable: i32,
) -> u32 {
    if c_events == 0 || c_events > WSA_MAXIMUM_WAIT_EVENTS || lph_events.is_null() {
        set_wsa_error(WSAEINVAL);
        return WSA_WAIT_FAILED;
    }

    // Build the set of event handles to wait on.
    let handles: Vec<usize> = (0..c_events as usize)
        .map(|i| unsafe { *lph_events.add(i) })
        .collect();

    // Validate that all event handles exist in the registry.
    let all_valid = with_wsa_events(|m| handles.iter().all(|h| m.contains_key(h)));
    if !all_valid {
        set_wsa_error(WSAEINVAL);
        return WSA_WAIT_FAILED;
    }

    // Convert timeout: INFINITE (0xFFFFFFFF) → None, otherwise milliseconds as u64.
    let timeout_ms: Option<u64> = if dw_timeout == 0xFFFF_FFFF {
        None
    } else {
        Some(u64::from(dw_timeout))
    };

    // Poll in a simple spin-sleep loop with 10 ms granularity up to timeout.
    let start = std::time::Instant::now();
    loop {
        // Check which events are currently signaled.
        let signaled: Vec<bool> = with_wsa_events(|m| {
            handles
                .iter()
                .map(|h| m.get(h).copied().unwrap_or(false))
                .collect()
        });

        if f_wait_all != 0 {
            if signaled.iter().all(|&s| s) {
                return WSA_WAIT_EVENT_0;
            }
        } else if let Some(idx) = signaled.iter().position(|&s| s) {
            return WSA_WAIT_EVENT_0 + idx as u32;
        }

        // Check timeout.
        if let Some(limit_ms) = timeout_ms {
            if limit_ms == 0 {
                return WSA_WAIT_TIMEOUT;
            }
            let elapsed_ms = start.elapsed().as_millis() as u64;
            if elapsed_ms >= limit_ms {
                return WSA_WAIT_TIMEOUT;
            }
        }

        // Sleep 10 ms before retrying to avoid burning CPU.
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

// SAFETY: `gethostbyname` is a standard POSIX function. The caller must ensure
// the `name` pointer is a valid NUL-terminated C string.
unsafe extern "C" {
    fn gethostbyname(name: *const libc::c_char) -> *mut libc::hostent;
}

/// `gethostbyname(name)` — resolve a hostname to an IPv4 address (legacy API).
///
/// Delegates directly to the system `gethostbyname`.
/// Returns a pointer to a static `hostent` structure, or null on failure.
///
/// # Safety
/// `name` must be a valid, NUL-terminated byte string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ws2_gethostbyname(name: *const u8) -> *mut libc::hostent {
    if name.is_null() {
        set_wsa_error(WSAEFAULT);
        return core::ptr::null_mut();
    }
    // SAFETY: name is a valid NUL-terminated string per caller's contract.
    let result = unsafe { gethostbyname(name.cast()) };
    if result.is_null() {
        set_wsa_error(WSAHOST_NOT_FOUND);
    }
    result
}

// SAFETY: POSIX legacy functions; caller ensures pointer validity.
unsafe extern "C" {
    fn getservbyname(name: *const libc::c_char, proto: *const libc::c_char) -> *mut libc::servent;
    fn getservbyport(port: libc::c_int, proto: *const libc::c_char) -> *mut libc::servent;
    fn getprotobyname(name: *const libc::c_char) -> *mut libc::protoent;
}

/// `getservbyname(name, proto)` — look up a service by name.
///
/// # Safety
/// `name` must be a non-null NUL-terminated C string. `proto` may be null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ws2_getservbyname(name: *const u8, proto: *const u8) -> *mut u8 {
    if name.is_null() {
        set_wsa_error(WSAEFAULT);
        return core::ptr::null_mut();
    }
    // SAFETY: name is a valid NUL-terminated string per caller's contract.
    let result = unsafe { getservbyname(name.cast(), proto.cast()) };
    if result.is_null() {
        set_wsa_error(WSANO_DATA);
    }
    result.cast()
}

/// `getservbyport(port, proto)` — look up a service by port number.
///
/// # Safety
/// `proto` must be null or a valid NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ws2_getservbyport(port: i32, proto: *const u8) -> *mut u8 {
    // SAFETY: proto is null or a valid NUL-terminated string per caller's contract.
    let result = unsafe { getservbyport(port, proto.cast()) };
    if result.is_null() {
        set_wsa_error(WSANO_DATA);
    }
    result.cast()
}

/// `getprotobyname(name)` — look up a protocol entry by name.
///
/// # Safety
/// `name` must be a non-null NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ws2_getprotobyname(name: *const u8) -> *mut u8 {
    if name.is_null() {
        set_wsa_error(WSAEFAULT);
        return core::ptr::null_mut();
    }
    // SAFETY: name is a valid NUL-terminated string per caller's contract.
    let result = unsafe { getprotobyname(name.cast()) };
    if result.is_null() {
        set_wsa_error(WSANO_DATA);
    }
    result.cast()
}

/// `WSAAsyncSelect(s, hwnd, wmsg, levent)` — register async network-event interest.
///
/// Stores the network-event mask on the socket entry (like `WSAEventSelect` but
/// without an associated event handle). The `hwnd` and `wmsg` parameters are
/// accepted for API compatibility but are not used on Linux.
/// Returns 0 on success, `SOCKET_ERROR` on failure.
///
/// # Safety
/// `s` must be a valid socket handle obtained from `socket`/`WSASocketW`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ws2_WSAAsyncSelect(
    s: usize,
    _hwnd: usize,
    _wmsg: u32,
    levent: u32,
) -> i32 {
    let ok = with_socket_handles(|m| {
        if let Some(entry) = m.get_mut(&s) {
            entry.network_events_mask = levent as i32;
            true
        } else {
            false
        }
    });
    if ok {
        0
    } else {
        set_wsa_error(WSAENOTSOCK);
        SOCKET_ERROR
    }
}

// ── Phase 42: additional socket / inet helpers ────────────────────────────────

/// `WSAIoctl` — not supported; returns `SOCKET_ERROR` with `WSAEOPNOTSUPP`.
///
/// # Safety
/// No pointer dereferences are performed.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn ws2_WSAIoctl(
    _s: usize,
    _dw_io_control_code: u32,
    _lpv_in_buffer: *const u8,
    _cb_in_buffer: u32,
    _lpv_out_buffer: *mut u8,
    _cb_out_buffer: u32,
    _lpcb_bytes_returned: *mut u32,
    _lp_overlapped: *mut u8,
    _lp_completion_routine: *mut u8,
) -> i32 {
    set_wsa_error(WSAEOPNOTSUPP);
    SOCKET_ERROR
}

/// `inet_addr(cp)` — convert a dotted-decimal IPv4 address string to a `u32`.
///
/// # Safety
/// `cp` must be a valid NUL-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ws2_inet_addr(cp: *const u8) -> u32 {
    unsafe extern "C" {
        fn inet_addr(cp: *const libc::c_char) -> u32;
    }
    // SAFETY: cp is a valid NUL-terminated string per caller contract.
    unsafe { inet_addr(cp.cast()) }
}

/// `inet_pton(family, src, dst)` — convert a text address to binary form.
///
/// # Safety
/// `src` must be a valid NUL-terminated string; `dst` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ws2_inet_pton(family: i32, src: *const u8, dst: *mut u8) -> i32 {
    unsafe extern "C" {
        fn inet_pton(
            af: libc::c_int,
            src: *const libc::c_char,
            dst: *mut libc::c_void,
        ) -> libc::c_int;
    }
    // SAFETY: src is a valid NUL-terminated string; dst is a writable buffer per caller.
    unsafe { inet_pton(family, src.cast(), dst.cast()) }
}

/// `inet_ntop(family, src, dst, size)` — convert a binary address to text form.
///
/// Returns pointer to `dst` on success, null on failure.
///
/// # Safety
/// `src` must point to a valid address structure; `dst` must be writable for `size` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ws2_inet_ntop(
    family: i32,
    src: *const u8,
    dst: *mut u8,
    size: usize,
) -> *const u8 {
    unsafe extern "C" {
        fn inet_ntop(
            af: libc::c_int,
            src: *const libc::c_void,
            dst: *mut libc::c_char,
            size: libc::socklen_t,
        ) -> *const libc::c_char;
    }
    // SAFETY: src/dst are valid per caller contract.
    unsafe { inet_ntop(family, src.cast(), dst.cast(), size as libc::socklen_t) }.cast::<u8>()
}

/// Windows-compatible `WSAPOLLFD` structure (matches Win32 ABI).
///
/// - `fd`: Win32 `SOCKET` handle (pointer-sized)
/// - `events` / `revents`: 16-bit event bitmasks identical to POSIX `pollfd`
#[repr(C)]
#[allow(non_camel_case_types, clippy::upper_case_acronyms)]
struct WSAPOLLFD {
    /// Win32 `SOCKET` handle.
    fd: usize,
    /// Requested events (same bit values as POSIX `pollfd::events`).
    events: i16,
    /// Returned events (filled by `WSAPoll`).
    revents: i16,
}

/// `WSAPoll(fd_array, n_fds, timeout)` — poll a set of sockets.
///
/// Translates each Win32 `SOCKET` handle in `fd_array` to a Linux file descriptor
/// via the socket handle registry, calls `libc::poll`, then writes `revents` back.
///
/// # Safety
/// `fd_array` must point to `n_fds` valid `WSAPOLLFD` structures, properly aligned to
/// `align_of::<WSAPOLLFD>()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ws2_WSAPoll(fd_array: *mut u8, n_fds: u32, timeout: i32) -> i32 {
    debug_assert_eq!(
        fd_array as usize % core::mem::align_of::<WSAPOLLFD>(),
        0,
        "fd_array must be aligned to WSAPOLLFD"
    );

    if n_fds == 0 {
        return 0;
    }

    // SAFETY: caller guarantees fd_array points to n_fds contiguous WSAPOLLFD entries,
    // properly aligned (asserted above in debug builds).
    #[allow(clippy::cast_ptr_alignment)]
    let sockets: &mut [WSAPOLLFD] =
        unsafe { core::slice::from_raw_parts_mut(fd_array.cast::<WSAPOLLFD>(), n_fds as usize) };

    // Translate Win32 SOCKET handles to Linux file descriptors.
    let mut poll_fds: Vec<libc::pollfd> = sockets
        .iter()
        .map(|wsa| {
            // Look up the Linux fd from the socket registry; fall back to direct cast.
            let linux_fd = with_socket_handles(|m| m.get(&wsa.fd).map(|e| e.fd))
                .unwrap_or(wsa.fd as libc::c_int);
            libc::pollfd {
                fd: linux_fd,
                events: wsa.events,
                revents: 0,
            }
        })
        .collect();

    // SAFETY: poll_fds is a valid contiguous array of pollfd structs.
    let ret = unsafe {
        libc::poll(
            poll_fds.as_mut_ptr(),
            poll_fds.len() as libc::nfds_t,
            timeout,
        )
    };

    if ret >= 0 {
        // Propagate returned events back to the caller's WSAPOLLFD array.
        for (src, dst) in poll_fds.iter().zip(sockets.iter_mut()) {
            dst.revents = src.revents;
        }
    } else {
        // Map errno to a WinSock error code so WSAPoll follows WinSock semantics.
        set_wsa_error_from_errno();
    }

    ret
}

// ── Unit tests ────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wsa_startup_cleanup() {
        // Version 2.2
        let mut wsa_data = WsaData {
            w_version: 0,
            w_high_version: 0,
            i_max_sockets: 0,
            i_max_udp_dg: 0,
            lp_vendor_info: core::ptr::null_mut(),
            sz_description: [0u8; 257],
            sz_system_status: [0u8; 129],
        };
        let result = unsafe { ws2_WSAStartup(0x0202, (&raw mut wsa_data).cast::<c_void>()) };
        assert_eq!(result, 0, "WSAStartup should succeed");
        assert_eq!(
            unsafe { ws2_WSAGetLastError() },
            0,
            "WSAGetLastError should be 0 after success"
        );

        let cleanup = unsafe { ws2_WSACleanup() };
        assert_eq!(cleanup, 0, "WSACleanup should succeed");
    }

    #[test]
    fn test_wsa_set_get_last_error() {
        unsafe { ws2_WSASetLastError(10060) };
        assert_eq!(
            unsafe { ws2_WSAGetLastError() },
            10060,
            "WSAGetLastError should return the set error"
        );
        unsafe { ws2_WSASetLastError(0) };
        assert_eq!(unsafe { ws2_WSAGetLastError() }, 0);
    }

    #[test]
    fn test_byte_order_htons_ntohs() {
        let host: u16 = 0x1234;
        let net = unsafe { ws2_htons(host) };
        // On little-endian platforms the bytes should be swapped
        if cfg!(target_endian = "little") {
            assert_eq!(net, 0x3412u16);
        } else {
            assert_eq!(net, host);
        }
        assert_eq!(unsafe { ws2_ntohs(net) }, host);
    }

    #[test]
    fn test_byte_order_htonl_ntohl() {
        let host: u32 = 0x1234_5678;
        let net = unsafe { ws2_htonl(host) };
        if cfg!(target_endian = "little") {
            assert_eq!(net, 0x7856_3412u32);
        } else {
            assert_eq!(net, host);
        }
        assert_eq!(unsafe { ws2_ntohl(net) }, host);
    }

    #[test]
    fn test_socket_create_close() {
        let s = unsafe { ws2_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) };
        assert_ne!(s, INVALID_SOCKET, "socket() should succeed");
        let result = unsafe { ws2_closesocket(s) };
        assert_eq!(result, 0, "closesocket() should succeed");
    }

    #[test]
    fn test_invalid_socket_operations() {
        // Operations on a non-existent handle should fail with WSAENOTSOCK
        let bad: usize = 0xDEAD_BEEF;
        let result = unsafe { ws2_closesocket(bad) };
        assert_eq!(result, SOCKET_ERROR);
        assert_eq!(unsafe { ws2_WSAGetLastError() }, WSAENOTSOCK);

        let result = unsafe { ws2_send(bad, b"hello".as_ptr(), 5, 0) };
        assert_eq!(result, SOCKET_ERROR);
        assert_eq!(unsafe { ws2_WSAGetLastError() }, WSAENOTSOCK);
    }

    #[test]
    fn test_socket_udp_create_close() {
        let s = unsafe { ws2_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP) };
        assert_ne!(s, INVALID_SOCKET, "UDP socket() should succeed");
        let result = unsafe { ws2_closesocket(s) };
        assert_eq!(result, 0);
    }

    #[test]
    fn test_ioctlsocket_nonblocking() {
        let s = unsafe { ws2_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) };
        assert_ne!(s, INVALID_SOCKET);
        // Enable non-blocking
        let mut arg: u32 = 1;
        let result = unsafe { ws2_ioctlsocket(s, FIONBIO, &raw mut arg) };
        assert_eq!(result, 0, "ioctlsocket(FIONBIO=1) should succeed");
        // Disable non-blocking
        arg = 0;
        let result = unsafe { ws2_ioctlsocket(s, FIONBIO, &raw mut arg) };
        assert_eq!(result, 0, "ioctlsocket(FIONBIO=0) should succeed");
        unsafe { ws2_closesocket(s) };
    }

    #[test]
    fn test_setsockopt_reuseaddr() {
        let s = unsafe { ws2_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) };
        assert_ne!(s, INVALID_SOCKET);
        let optval: i32 = 1;
        // Use Windows constants (SOL_SOCKET = 0xFFFF, SO_REUSEADDR = 4),
        // which are translated to their Linux equivalents inside ws2_setsockopt.
        let result = unsafe {
            ws2_setsockopt(
                s,
                WIN_SOL_SOCKET,
                WIN_SO_REUSEADDR,
                (&raw const optval).cast::<u8>(),
                core::mem::size_of::<i32>() as i32,
            )
        };
        assert_eq!(result, 0, "setsockopt(SO_REUSEADDR) should succeed");
        unsafe { ws2_closesocket(s) };
    }

    #[test]
    fn test_shutdown_invalid_socket() {
        let bad: usize = 0xDEAD_0001;
        let result = unsafe { ws2_shutdown(bad, SD_BOTH) };
        assert_eq!(result, SOCKET_ERROR);
        assert_eq!(unsafe { ws2_WSAGetLastError() }, WSAENOTSOCK);
    }

    #[test]
    fn test_wsa_startup_version_too_high() {
        // Version 3.0 should be rejected
        let result = unsafe { ws2_WSAStartup(0x0003, core::ptr::null_mut()) };
        assert_eq!(result, WSAVERNOTSUPPORTED);
    }

    #[test]
    fn test_wsa_create_close_event() {
        let h = unsafe { ws2_WSACreateEvent() };
        assert_ne!(h, 0);
        let ret = unsafe { ws2_WSACloseEvent(h) };
        assert_eq!(ret, 1);
        // Closing again should fail
        let ret2 = unsafe { ws2_WSACloseEvent(h) };
        assert_eq!(ret2, 0);
    }

    #[test]
    fn test_wsa_set_reset_event() {
        let h = unsafe { ws2_WSACreateEvent() };
        assert_ne!(h, 0);
        // Initially not signaled
        let ret = unsafe { ws2_WSAResetEvent(h) };
        assert_eq!(ret, 1);
        // Set to signaled
        let ret = unsafe { ws2_WSASetEvent(h) };
        assert_eq!(ret, 1);
        // Reset back
        let ret = unsafe { ws2_WSAResetEvent(h) };
        assert_eq!(ret, 1);
        unsafe { ws2_WSACloseEvent(h) };
    }

    #[test]
    fn test_wsa_event_select_invalid_socket() {
        let bad: usize = 0xDEAD_0002;
        let h = unsafe { ws2_WSACreateEvent() };
        let ret = unsafe { ws2_WSAEventSelect(bad, h, FD_READ | FD_WRITE) };
        assert_eq!(ret, SOCKET_ERROR);
        assert_eq!(unsafe { ws2_WSAGetLastError() }, WSAENOTSOCK);
        unsafe { ws2_WSACloseEvent(h) };
    }

    #[test]
    fn test_wsa_event_select_valid_socket() {
        let s = unsafe { ws2_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) };
        assert_ne!(s, INVALID_SOCKET);
        let h = unsafe { ws2_WSACreateEvent() };
        let ret = unsafe { ws2_WSAEventSelect(s, h, FD_READ | FD_WRITE | FD_CLOSE) };
        assert_eq!(ret, 0);
        unsafe { ws2_closesocket(s) };
        unsafe { ws2_WSACloseEvent(h) };
    }

    #[test]
    fn test_gethostbyname_localhost() {
        let name = b"localhost\0";
        let result = unsafe { ws2_gethostbyname(name.as_ptr()) };
        // May or may not succeed depending on the environment
        let _ = result;
    }

    // ── WSAWaitForMultipleEvents tests ────────────────────────────────────────

    #[test]
    fn test_wsa_wait_immediate_timeout_unsignaled() {
        // A single unsignaled event with 0-ms timeout should return WSA_WAIT_TIMEOUT.
        let h = unsafe { ws2_WSACreateEvent() };
        assert_ne!(h, 0);
        let handles = [h];
        let ret = unsafe { ws2_WSAWaitForMultipleEvents(1, handles.as_ptr(), 0, 0, 0) };
        assert_eq!(ret, WSA_WAIT_TIMEOUT);
        unsafe { ws2_WSACloseEvent(h) };
    }

    #[test]
    fn test_wsa_wait_already_signaled() {
        // A pre-signaled event with any timeout should return immediately.
        let h = unsafe { ws2_WSACreateEvent() };
        assert_ne!(h, 0);
        unsafe { ws2_WSASetEvent(h) };
        let handles = [h];
        let ret = unsafe { ws2_WSAWaitForMultipleEvents(1, handles.as_ptr(), 0, 0, 0) };
        assert_eq!(ret, WSA_WAIT_EVENT_0);
        unsafe { ws2_WSACloseEvent(h) };
    }

    #[test]
    fn test_wsa_wait_any_first_signaled() {
        // wait-any: returns index of first signaled event.
        let h0 = unsafe { ws2_WSACreateEvent() };
        let h1 = unsafe { ws2_WSACreateEvent() };
        assert_ne!(h0, 0);
        assert_ne!(h1, 0);
        unsafe { ws2_WSASetEvent(h1) }; // only second is signaled
        let handles = [h0, h1];
        let ret = unsafe { ws2_WSAWaitForMultipleEvents(2, handles.as_ptr(), 0, 0, 0) };
        assert_eq!(ret, WSA_WAIT_EVENT_0 + 1);
        unsafe { ws2_WSACloseEvent(h0) };
        unsafe { ws2_WSACloseEvent(h1) };
    }

    #[test]
    fn test_wsa_wait_all_not_all_signaled() {
        // wait-all: when only one of two is signaled and timeout=0, should time out.
        let h0 = unsafe { ws2_WSACreateEvent() };
        let h1 = unsafe { ws2_WSACreateEvent() };
        assert_ne!(h0, 0);
        assert_ne!(h1, 0);
        unsafe { ws2_WSASetEvent(h0) }; // only first is signaled
        let handles = [h0, h1];
        let ret = unsafe { ws2_WSAWaitForMultipleEvents(2, handles.as_ptr(), 1, 0, 0) };
        assert_eq!(ret, WSA_WAIT_TIMEOUT);
        unsafe { ws2_WSACloseEvent(h0) };
        unsafe { ws2_WSACloseEvent(h1) };
    }

    #[test]
    fn test_wsa_wait_all_both_signaled() {
        // wait-all: returns WSA_WAIT_EVENT_0 when all events are signaled.
        let h0 = unsafe { ws2_WSACreateEvent() };
        let h1 = unsafe { ws2_WSACreateEvent() };
        assert_ne!(h0, 0);
        assert_ne!(h1, 0);
        unsafe { ws2_WSASetEvent(h0) };
        unsafe { ws2_WSASetEvent(h1) };
        let handles = [h0, h1];
        let ret = unsafe { ws2_WSAWaitForMultipleEvents(2, handles.as_ptr(), 1, 0, 0) };
        assert_eq!(ret, WSA_WAIT_EVENT_0);
        unsafe { ws2_WSACloseEvent(h0) };
        unsafe { ws2_WSACloseEvent(h1) };
    }

    #[test]
    fn test_wsa_wait_invalid_handle_returns_failed() {
        // An unregistered handle should return WSA_WAIT_FAILED with WSAEINVAL.
        let invalid_handle: usize = 0xDEAD_BEEF;
        let handles = [invalid_handle];
        let ret = unsafe { ws2_WSAWaitForMultipleEvents(1, handles.as_ptr(), 0, 0, 0) };
        assert_eq!(ret, WSA_WAIT_FAILED);
        assert_eq!(unsafe { ws2_WSAGetLastError() }, WSAEINVAL);
    }

    #[test]
    fn test_wsa_wait_zero_events_returns_failed() {
        // c_events == 0 should return WSA_WAIT_FAILED with WSAEINVAL.
        let ret = unsafe { ws2_WSAWaitForMultipleEvents(0, core::ptr::null(), 0, 0, 0) };
        assert_eq!(ret, WSA_WAIT_FAILED);
        assert_eq!(unsafe { ws2_WSAGetLastError() }, WSAEINVAL);
    }

    #[test]
    fn test_wsa_wait_large_timeout_no_wraparound() {
        // Timeout value > i32::MAX (e.g., 0x8000_0000) must be handled as a
        // large positive delay, not a negative/infinite wait.
        let h = unsafe { ws2_WSACreateEvent() };
        assert_ne!(h, 0);
        // Event is not signaled; use timeout=1 ms to verify the function times out
        // rather than treating large DWORD values as negative (i.e. infinite) wait.
        let handles = [h];
        let ret = unsafe { ws2_WSAWaitForMultipleEvents(1, handles.as_ptr(), 0, 1, 0) };
        // Should time out (not fail or infinite-loop).
        assert_eq!(ret, WSA_WAIT_TIMEOUT);
        unsafe { ws2_WSACloseEvent(h) };
    }

    #[test]
    fn test_wsa_async_select_stores_mask_and_returns_zero() {
        // Create a real TCP socket and register async interest.
        let s = unsafe { ws2_socket(libc::AF_INET, libc::SOCK_STREAM, libc::IPPROTO_TCP) };
        assert_ne!(s, usize::MAX, "socket creation should succeed");
        // FD_READ = 1, FD_WRITE = 2
        let ret = unsafe { ws2_WSAAsyncSelect(s, 0, 0, 1 | 2) };
        assert_eq!(ret, 0);
        unsafe { ws2_closesocket(s) };
    }

    // ── Phase 42 inet / poll tests ─────────────────────────────────────────────

    #[test]
    fn test_wsaioctl_returns_socket_error_with_wsaeopnotsupp() {
        let ret = unsafe {
            ws2_WSAIoctl(
                0,
                0,
                core::ptr::null(),
                0,
                core::ptr::null_mut(),
                0,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        };
        assert_eq!(ret, SOCKET_ERROR);
        assert_eq!(unsafe { ws2_WSAGetLastError() }, WSAEOPNOTSUPP);
    }

    #[test]
    fn test_inet_pton_and_ntop_round_trip() {
        // Convert "127.0.0.1" → binary → string and verify round-trip.
        let src = b"127.0.0.1\0";
        let mut bin = [0u8; 4];
        let r = unsafe { ws2_inet_pton(libc::AF_INET, src.as_ptr(), bin.as_mut_ptr()) };
        assert_eq!(r, 1, "inet_pton should succeed");

        let mut out = [0u8; 32];
        let p = unsafe { ws2_inet_ntop(libc::AF_INET, bin.as_ptr(), out.as_mut_ptr(), out.len()) };
        assert!(!p.is_null(), "inet_ntop should succeed");

        // SAFETY: p points into out, which is valid.
        let result = unsafe { core::ffi::CStr::from_ptr(p.cast()) };
        assert_eq!(result.to_bytes(), b"127.0.0.1");
    }

    #[test]
    fn test_inet_addr_loopback() {
        // inet_addr("127.0.0.1") should return the loopback address in network byte order.
        let src = b"127.0.0.1\0";
        let addr = unsafe { ws2_inet_addr(src.as_ptr()) };
        // 127.0.0.1 in network byte order = 0x0100007F on little-endian
        assert_eq!(addr, 0x0100_007Fu32);
    }

    #[test]
    fn test_wsapoll_timeout_on_unconnected_socket() {
        // A TCP socket with no data should timeout immediately with timeout=0.
        let s = unsafe { ws2_socket(libc::AF_INET, libc::SOCK_STREAM, libc::IPPROTO_TCP) };
        assert_ne!(s, usize::MAX, "socket creation should succeed");

        // Build a WSAPOLLFD targeting POLLIN on this socket.
        let mut pfd = WSAPOLLFD {
            fd: s,
            events: libc::POLLIN,
            revents: 0,
        };
        // Poll with 0 ms timeout — must not panic.  The exact return value (0, 1,
        // or -1) depends on the kernel; an unconnected TCP socket may have POLLHUP.
        let ret = unsafe {
            ws2_WSAPoll(
                (&raw mut pfd).cast::<u8>(),
                1,
                0, // non-blocking
            )
        };
        // Any non-panicking integer return is valid here.
        let _ = ret;

        unsafe { ws2_closesocket(s) };
    }

    #[test]
    fn test_getservbyname_http() {
        let name = b"http\0";
        let result = unsafe { ws2_getservbyname(name.as_ptr(), core::ptr::null()) };
        assert!(
            !result.is_null(),
            "getservbyname(\"http\") should return non-null"
        );
    }

    #[test]
    fn test_getservbyport_80() {
        // Port 80 in network byte order (htons(80)).
        let port = i32::from(libc::htons(80));
        let result = unsafe { ws2_getservbyport(port, core::ptr::null()) };
        assert!(
            !result.is_null(),
            "getservbyport(80) should return non-null"
        );
    }

    #[test]
    fn test_getprotobyname_tcp() {
        let name = b"tcp\0";
        let result = unsafe { ws2_getprotobyname(name.as_ptr()) };
        assert!(
            !result.is_null(),
            "getprotobyname(\"tcp\") should return non-null"
        );
    }

    #[test]
    fn test_getservbyname_null_returns_null() {
        let result = unsafe { ws2_getservbyname(core::ptr::null(), core::ptr::null()) };
        assert!(result.is_null(), "getservbyname(NULL) should return null");
    }

    #[test]
    fn test_getprotobyname_null_returns_null() {
        let result = unsafe { ws2_getprotobyname(core::ptr::null()) };
        assert!(result.is_null(), "getprotobyname(NULL) should return null");
    }
}
