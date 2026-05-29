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

#[derive(Serialize, Deserialize, Debug)]
struct BLOut {
    bound_port: u16,
    peer_port: u16,
    bytes: String,
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
}
