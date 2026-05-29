// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-held TCP listener probes.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::handlers::{HandlerCtx, HandlerError, HandlerToken};
use crate::register_handler;

use super::agents::AgentName;
use super::registry::Registry;

const LISTEN_BASIC: HandlerToken<(), BLOut> = HandlerToken::new("broker_listener.listen_basic");
const CONNECT_BASIC: HandlerToken<(), BLOut> = HandlerToken::new("broker_listener.connect_basic");
const RAW_ICMP_ECHO: HandlerToken<(), RawOut> = HandlerToken::new("broker_listener.raw_icmp_echo");

#[derive(Serialize, Deserialize, Debug)]
struct BLOut {
    bound_port: u16,
    peer_port: u16,
    bytes: String,
}

#[derive(Serialize, Deserialize, Debug)]
enum RawOut {
    PermissionDenied,
    EchoSucceeded,
}

struct Fd(i32);

impl Fd {
    fn new(fd: i32, what: &str) -> Result<Self, HandlerError> {
        if fd < 0 {
            Err(HandlerError(format!(
                "{what}: {}",
                std::io::Error::last_os_error()
            )))
        } else {
            Ok(Self(fd))
        }
    }
}

impl Drop for Fd {
    fn drop(&mut self) {
        // SAFETY: `self.0` is an fd owned by this RAII wrapper.
        unsafe { libc::close(self.0) };
    }
}

fn sockaddr_loopback_any() -> libc::sockaddr_in {
    libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: 0u16.to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(Ipv4Addr::LOCALHOST.octets()),
        },
        sin_zero: [0; 8],
    }
}

fn sockaddr_to_v4(addr: libc::sockaddr_in) -> SocketAddrV4 {
    SocketAddrV4::new(
        Ipv4Addr::from(addr.sin_addr.s_addr.to_ne_bytes()),
        u16::from_be(addr.sin_port),
    )
}

async fn handle_listen_basic(_args: (), _ctx: &mut HandlerCtx<'_>) -> Result<BLOut, HandlerError> {
    // SAFETY: socket has no pointer arguments.
    let listener = Fd::new(
        unsafe {
            libc::socket(
                libc::AF_INET,
                libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                0,
            )
        },
        "socket(AF_INET, SOCK_STREAM)",
    )?;

    let bind_addr = sockaddr_loopback_any();
    // SAFETY: `bind_addr` points to a valid sockaddr_in.
    let rc = unsafe {
        libc::bind(
            listener.0,
            (&bind_addr as *const libc::sockaddr_in).cast::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(HandlerError(format!(
            "bind: {}",
            std::io::Error::last_os_error()
        )));
    }

    // SAFETY: listen has no pointer arguments.
    if unsafe { libc::listen(listener.0, 5) } != 0 {
        return Err(HandlerError(format!(
            "listen: {}",
            std::io::Error::last_os_error()
        )));
    }

    // SAFETY: zeroed sockaddr_in is immediately filled by getsockname.
    let mut actual: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut actual_len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    // SAFETY: `actual` and `actual_len` are valid output pointers.
    let rc = unsafe {
        libc::getsockname(
            listener.0,
            (&mut actual as *mut libc::sockaddr_in).cast::<libc::sockaddr>(),
            &mut actual_len,
        )
    };
    if rc != 0 {
        return Err(HandlerError(format!(
            "getsockname: {}",
            std::io::Error::last_os_error()
        )));
    }
    let bound_addr = sockaddr_to_v4(actual);
    if bound_addr.port() == 0 {
        return Err(HandlerError("getsockname returned port 0".into()));
    }

    let connect_addr = if bound_addr.ip().is_unspecified() {
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, bound_addr.port())
    } else {
        bound_addr
    };
    let connector = thread::spawn(move || -> Result<(), String> {
        // SAFETY: socket has no pointer arguments.
        let fd = unsafe {
            libc::socket(
                libc::AF_INET,
                libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                0,
            )
        };
        if fd < 0 {
            return Err(format!("socket: {}", std::io::Error::last_os_error()));
        }
        let _fd = Fd(fd);
        let sockaddr = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: connect_addr.port().to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes(connect_addr.ip().octets()),
            },
            sin_zero: [0; 8],
        };
        // SAFETY: `sockaddr` points to a valid sockaddr_in.
        let rc = unsafe {
            libc::connect(
                fd,
                (&sockaddr as *const libc::sockaddr_in).cast::<libc::sockaddr>(),
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EINPROGRESS) {
                return Err(format!("connect: {err}"));
            }
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            // SAFETY: `fd` is valid and the payload pointer is valid for two bytes.
            let n = unsafe { libc::write(fd, b"hi".as_ptr().cast(), 2) };
            if n == 2 {
                return Ok(());
            }
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EAGAIN)
                && err.raw_os_error() != Some(libc::EWOULDBLOCK)
            {
                return Err(format!("write n={n} err={err}"));
            }
            if Instant::now() >= deadline {
                return Err("write timed out".into());
            }
            thread::sleep(Duration::from_millis(10));
        }
    });

    // SAFETY: zeroed sockaddr_in is immediately filled by accept.
    let mut peer: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let deadline = Instant::now() + Duration::from_secs(5);
    let _client = loop {
        let mut peer_len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        // SAFETY: `peer` and `peer_len` are valid output pointers.
        let fd = unsafe {
            libc::accept(
                listener.0,
                (&mut peer as *mut libc::sockaddr_in).cast::<libc::sockaddr>(),
                &mut peer_len,
            )
        };
        if fd >= 0 {
            break Fd(fd);
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EAGAIN) && err.raw_os_error() != Some(libc::EWOULDBLOCK)
        {
            return Err(HandlerError(format!("accept: {err}")));
        }
        if Instant::now() >= deadline {
            if connector.is_finished() {
                connector
                    .join()
                    .map_err(|_| HandlerError("connector panicked".into()))?
                    .map_err(HandlerError)?;
                return Err(HandlerError("connector exited before accept".into()));
            }
            return Err(HandlerError(
                "accept timed out waiting for connector".into(),
            ));
        }
        thread::sleep(Duration::from_millis(10));
    };

    drop(connector);

    Ok(BLOut {
        bound_port: bound_addr.port(),
        peer_port: sockaddr_to_v4(peer).port(),
        bytes: "accepted".into(),
    })
}

fn icmp_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum = sum.wrapping_add(u16::from_be_bytes([chunk[0], chunk[1]]) as u32);
    }
    if let Some(&byte) = chunks.remainder().first() {
        sum = sum.wrapping_add(u16::from_be_bytes([byte, 0]) as u32);
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

async fn handle_raw_icmp_echo(
    _args: (),
    _ctx: &mut HandlerCtx<'_>,
) -> Result<RawOut, HandlerError> {
    // SAFETY: socket has no pointer arguments.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP) };
    if fd < 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EPERM) {
            return Ok(RawOut::PermissionDenied);
        }
        return Err(HandlerError(format!("socket failed: {err}")));
    }
    let raw = Fd(fd);

    // SAFETY: fcntl does not dereference pointers for F_GETFL/F_SETFL.
    let flags = unsafe { libc::fcntl(raw.0, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(raw.0, libc::F_SETFL, flags | libc::O_NONBLOCK) } != 0 {
        return Err(HandlerError(format!(
            "fcntl nonblock: {}",
            std::io::Error::last_os_error()
        )));
    }

    let ident = (std::process::id() as u16).to_be_bytes();
    let seq = 1u16.to_be_bytes();
    let mut packet = Vec::from([8u8, 0, 0, 0, ident[0], ident[1], seq[0], seq[1]]);
    packet.extend_from_slice(b"litebox-raw-icmp");
    let checksum = icmp_checksum(&packet).to_be_bytes();
    packet[2] = checksum[0];
    packet[3] = checksum[1];

    let dst = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(Ipv4Addr::LOCALHOST.octets()),
        },
        sin_zero: [0; 8],
    };
    // SAFETY: `dst` points to a valid sockaddr_in and `packet` is a valid buffer.
    let sent = unsafe {
        libc::sendto(
            raw.0,
            packet.as_ptr().cast(),
            packet.len(),
            0,
            (&dst as *const libc::sockaddr_in).cast::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if sent != packet.len() as isize {
        return Err(HandlerError(format!(
            "sendto sent={sent}: {}",
            std::io::Error::last_os_error()
        )));
    }

    let deadline = Instant::now() + Duration::from_secs(2);
    let mut buf = [0u8; 512];
    loop {
        // SAFETY: `raw` is valid and `buf` is writable for its full length.
        let n = unsafe { libc::recv(raw.0, buf.as_mut_ptr().cast(), buf.len(), 0) };
        if n > 0 {
            let n = n as usize;
            if n >= 28 {
                let ihl = usize::from(buf[0] & 0x0f) * 4;
                if ihl >= 20 && n >= ihl + 8 {
                    let icmp = &buf[ihl..n];
                    if icmp[0] == 0
                        && icmp[1] == 0
                        && icmp[4] == ident[0]
                        && icmp[5] == ident[1]
                        && icmp[6] == seq[0]
                        && icmp[7] == seq[1]
                    {
                        return Ok(RawOut::EchoSucceeded);
                    }
                }
            }
        } else {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EAGAIN)
                && err.raw_os_error() != Some(libc::EWOULDBLOCK)
            {
                return Err(HandlerError(format!("recv: {err}")));
            }
        }
        if Instant::now() >= deadline {
            return Err(HandlerError("timed out waiting for ICMP echo reply".into()));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

async fn handle_connect_basic(_args: (), _ctx: &mut HandlerCtx<'_>) -> Result<BLOut, HandlerError> {
    // SAFETY: socket has no pointer arguments.
    let listener = Fd::new(
        unsafe {
            libc::socket(
                libc::AF_INET,
                libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                0,
            )
        },
        "listener socket(AF_INET, SOCK_STREAM)",
    )?;

    let bind_addr = sockaddr_loopback_any();
    // SAFETY: `bind_addr` points to a valid sockaddr_in.
    let rc = unsafe {
        libc::bind(
            listener.0,
            (&bind_addr as *const libc::sockaddr_in).cast::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(HandlerError(format!(
            "bind: {}",
            std::io::Error::last_os_error()
        )));
    }

    // SAFETY: listen has no pointer arguments.
    if unsafe { libc::listen(listener.0, 5) } != 0 {
        return Err(HandlerError(format!(
            "listen: {}",
            std::io::Error::last_os_error()
        )));
    }

    // SAFETY: zeroed sockaddr_in is immediately filled by getsockname.
    let mut actual: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut actual_len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    // SAFETY: `actual` and `actual_len` are valid output pointers.
    let rc = unsafe {
        libc::getsockname(
            listener.0,
            (&mut actual as *mut libc::sockaddr_in).cast::<libc::sockaddr>(),
            &mut actual_len,
        )
    };
    if rc != 0 {
        return Err(HandlerError(format!(
            "getsockname: {}",
            std::io::Error::last_os_error()
        )));
    }
    let bound_addr = sockaddr_to_v4(actual);
    if bound_addr.port() == 0 {
        return Err(HandlerError("getsockname returned port 0".into()));
    }

    let connect_addr = if bound_addr.ip().is_unspecified() {
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, bound_addr.port())
    } else {
        bound_addr
    };
    let connector = thread::spawn(move || -> Result<(), String> {
        // SAFETY: socket has no pointer arguments.
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        if fd < 0 {
            return Err(format!("socket: {}", std::io::Error::last_os_error()));
        }
        let _fd = Fd(fd);
        let sockaddr = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: connect_addr.port().to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes(connect_addr.ip().octets()),
            },
            sin_zero: [0; 8],
        };
        // SAFETY: `sockaddr` points to a valid sockaddr_in.
        if unsafe {
            libc::connect(
                fd,
                (&sockaddr as *const libc::sockaddr_in).cast::<libc::sockaddr>(),
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        } != 0
        {
            return Err(format!("connect: {}", std::io::Error::last_os_error()));
        }
        // SAFETY: `fd` is valid and the payload pointer is valid for five bytes.
        let n = unsafe { libc::write(fd, b"hello".as_ptr().cast(), 5) };
        if n != 5 {
            return Err(format!("write n={n}: {}", std::io::Error::last_os_error()));
        }
        // SAFETY: shutdown has no pointer arguments.
        if unsafe { libc::shutdown(fd, libc::SHUT_WR) } != 0 {
            return Err(format!("shutdown: {}", std::io::Error::last_os_error()));
        }
        Ok(())
    });

    // SAFETY: zeroed sockaddr_in is immediately filled by accept.
    let mut peer: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let deadline = Instant::now() + Duration::from_secs(5);
    let conn = loop {
        let mut peer_len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        // SAFETY: `peer` and `peer_len` are valid output pointers.
        let fd = unsafe {
            libc::accept(
                listener.0,
                (&mut peer as *mut libc::sockaddr_in).cast::<libc::sockaddr>(),
                &mut peer_len,
            )
        };
        if fd >= 0 {
            break Fd(fd);
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EAGAIN) && err.raw_os_error() != Some(libc::EWOULDBLOCK)
        {
            return Err(HandlerError(format!("accept: {err}")));
        }
        if Instant::now() >= deadline {
            return Err(HandlerError(
                "accept timed out waiting for connector".into(),
            ));
        }
        thread::sleep(Duration::from_millis(10));
    };

    let mut buf = [0u8; 5];
    // SAFETY: `conn` is valid and `buf` is valid for five bytes.
    let n = unsafe { libc::read(conn.0, buf.as_mut_ptr().cast(), buf.len()) };
    if n != 5 {
        return Err(HandlerError(format!(
            "read n={n}: {}",
            std::io::Error::last_os_error()
        )));
    }
    if &buf != b"hello" {
        return Err(HandlerError(format!("read bytes: {buf:?}")));
    }

    connector
        .join()
        .map_err(|_| HandlerError("connector panicked".into()))?
        .map_err(HandlerError)?;

    Ok(BLOut {
        bound_port: bound_addr.port(),
        peer_port: sockaddr_to_v4(peer).port(),
        bytes: String::from_utf8_lossy(&buf).into_owned(),
    })
}

pub(crate) fn register_broker_listener_tests(reg: &mut Registry<'_>) {
    register_handler!(LISTEN_BASIC, handle_listen_basic);
    register_handler!(CONNECT_BASIC, handle_connect_basic);
    register_handler!(RAW_ICMP_ECHO, handle_raw_icmp_echo);
    reg.single_agent_handler_test(
        "broker_listener",
        "listen_basic",
        "BL.listen_basic.pie-glibc.dpg1",
        AgentName::Dpg1,
        &LISTEN_BASIC,
        |out| {
            Ok(format!(
                "bound={} peer={} bytes={}",
                out.bound_port, out.peer_port, out.bytes
            ))
        },
    );
    reg.single_agent_handler_test(
        "broker_listener",
        "connect_basic",
        "BL.connect_basic.pie-glibc.dpg1",
        AgentName::Dpg1,
        &CONNECT_BASIC,
        |out| {
            Ok(format!(
                "bound={} peer={} bytes={}",
                out.bound_port, out.peer_port, out.bytes
            ))
        },
    );
    reg.single_agent_handler_test(
        "broker_listener",
        "raw_icmp_echo",
        "BL.raw_icmp_echo.pie-glibc.dpg1",
        AgentName::Dpg1,
        &RAW_ICMP_ECHO,
        |out| {
            // Raw sockets require CAP_NET_RAW; EPERM is the expected PASS outcome
            // in many Docker/Linux environments, while privileged environments can
            // exercise the actual loopback echo path.
            match out {
                RawOut::PermissionDenied => Ok("raw_icmp=PermissionDenied".to_string()),
                RawOut::EchoSucceeded => Ok("raw_icmp=EchoSucceeded".to_string()),
            }
        },
    );
}
