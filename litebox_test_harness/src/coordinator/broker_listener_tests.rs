// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-held TCP listener probes.

use std::net::{Ipv4Addr, SocketAddrV4, ToSocketAddrs, UdpSocket};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::handlers::{HandlerCtx, HandlerError, HandlerToken};
use crate::register_handler;

use super::agents::AgentName;
use super::registry::Registry;

const LISTEN_BASIC: HandlerToken<(), BLOut> = HandlerToken::new("broker_listener.listen_basic");
const CONNECT_BASIC: HandlerToken<(), BLOut> = HandlerToken::new("broker_listener.connect_basic");
const UDP_RECVFROM_REMOTE_ADDR: HandlerToken<(), BLOut> =
    HandlerToken::new("broker_listener.udp_recvfrom_remote_addr");
const UDP_TRUNCATION: HandlerToken<(), BLOut> = HandlerToken::new("broker_listener.udp_truncation");
const RAW_ICMP_ECHO: HandlerToken<(), RawOut> = HandlerToken::new("broker_listener.raw_icmp_echo");
const DNS_RESOLVE: HandlerToken<(), DnsOut> = HandlerToken::new("broker_listener.dns_resolve");
const DNS_RESOLVE_CNAME_HEAVY: HandlerToken<(), DnsOut> =
    HandlerToken::new("broker_listener.dns_resolve_cname_heavy");

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

#[derive(Serialize, Deserialize, Debug)]
struct DnsOut {
    localhost_addrs: Vec<String>,
    remote_addrs: Vec<String>,
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

fn sockaddr_from_v4(addr: SocketAddrV4) -> libc::sockaddr_in {
    libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: addr.port().to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(addr.ip().octets()),
        },
        sin_zero: [0; 8],
    }
}

fn getsockname_v4(fd: i32, what: &str) -> Result<SocketAddrV4, HandlerError> {
    // SAFETY: zeroed sockaddr_in is immediately filled by getsockname.
    let mut actual: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut actual_len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    // SAFETY: `actual` and `actual_len` are valid output pointers.
    let rc = unsafe {
        libc::getsockname(
            fd,
            (&mut actual as *mut libc::sockaddr_in).cast::<libc::sockaddr>(),
            &mut actual_len,
        )
    };
    if rc != 0 {
        return Err(HandlerError(format!(
            "{what}: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(sockaddr_to_v4(actual))
}

fn bind_loopback_any(fd: i32) -> Result<SocketAddrV4, HandlerError> {
    let bind_addr = sockaddr_loopback_any();
    // SAFETY: `bind_addr` points to a valid sockaddr_in.
    let rc = unsafe {
        libc::bind(
            fd,
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
    getsockname_v4(fd, "getsockname")
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
        // Documented "raw not available in this environment" outcomes:
        //   - EPERM: broker holds the raw socket but the host kernel
        //     denied it (lacks CAP_NET_RAW), or sandbox policy denies.
        //     Returned when LITEBOX_BROKER_INET_RAW=1 + Docker without
        //     --cap-add NET_RAW.
        //   - EPROTONOSUPPORT: no raw provider is installed at all, so
        //     the shim's worker-local stack reports "this protocol is
        //     not supported here." Returned when LITEBOX_BROKER_INET_RAW
        //     is unset / =0 (the F.1-flip default).
        // Both are accurate kernel-shaped errnos; the probe accepts
        // either as the same "raw is restricted/unavailable" outcome.
        if matches!(
            err.raw_os_error(),
            Some(libc::EPERM) | Some(libc::EPROTONOSUPPORT)
        ) {
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

async fn handle_udp_recvfrom_remote_addr(
    _args: (),
    _ctx: &mut HandlerCtx<'_>,
) -> Result<BLOut, HandlerError> {
    // SAFETY: socket has no pointer arguments.
    let recv = Fd::new(
        unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) },
        "recv socket(AF_INET, SOCK_DGRAM)",
    )?;
    let bound = bind_loopback_any(recv.0)?;

    let sender = thread::spawn(move || -> Result<SocketAddrV4, String> {
        // SAFETY: socket has no pointer arguments.
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
        if fd < 0 {
            return Err(format!("send socket: {}", std::io::Error::last_os_error()));
        }
        let _fd = Fd(fd);
        let dst = sockaddr_from_v4(bound);
        // SAFETY: `dst` and payload pointers are valid for the provided lengths.
        let n = unsafe {
            libc::sendto(
                fd,
                b"hi".as_ptr().cast(),
                2,
                0,
                (&dst as *const libc::sockaddr_in).cast::<libc::sockaddr>(),
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };
        if n != 2 {
            return Err(format!("sendto n={n}: {}", std::io::Error::last_os_error()));
        }
        getsockname_v4(fd, "sender getsockname").map_err(|e| e.0)
    });

    let mut buf = [0u8; 8];
    // SAFETY: zeroed sockaddr_in is immediately filled by recvfrom.
    let mut peer: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut peer_len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    // SAFETY: `recv`, `buf`, `peer`, and `peer_len` are valid.
    let n = unsafe {
        libc::recvfrom(
            recv.0,
            buf.as_mut_ptr().cast(),
            buf.len(),
            0,
            (&mut peer as *mut libc::sockaddr_in).cast::<libc::sockaddr>(),
            &mut peer_len,
        )
    };
    if n != 2 {
        return Err(HandlerError(format!(
            "recvfrom n={n}: {}",
            std::io::Error::last_os_error()
        )));
    }
    if &buf[..2] != b"hi" {
        return Err(HandlerError(format!("recvfrom bytes: {:?}", &buf[..2])));
    }
    let sender_addr = sender
        .join()
        .map_err(|_| HandlerError("sender panicked".into()))?
        .map_err(HandlerError)?;
    let peer_addr = sockaddr_to_v4(peer);
    if peer_addr.port() != sender_addr.port() {
        return Err(HandlerError(format!(
            "peer port {} != sender port {}",
            peer_addr.port(),
            sender_addr.port()
        )));
    }

    Ok(BLOut {
        bound_port: bound.port(),
        peer_port: peer_addr.port(),
        bytes: String::from_utf8_lossy(&buf[..2]).into_owned(),
    })
}

async fn handle_udp_truncation(
    _args: (),
    _ctx: &mut HandlerCtx<'_>,
) -> Result<BLOut, HandlerError> {
    // SAFETY: socket has no pointer arguments.
    let recv = Fd::new(
        unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) },
        "recv socket(AF_INET, SOCK_DGRAM)",
    )?;
    let bound = bind_loopback_any(recv.0)?;

    let sender = thread::spawn(move || -> Result<SocketAddrV4, String> {
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
        if fd < 0 {
            return Err(format!("send socket: {}", std::io::Error::last_os_error()));
        }
        let _fd = Fd(fd);
        let payload = vec![b'x'; 4096];
        let dst = sockaddr_from_v4(bound);
        // SAFETY: `dst` and payload pointers are valid for the provided lengths.
        let n = unsafe {
            libc::sendto(
                fd,
                payload.as_ptr().cast(),
                payload.len(),
                0,
                (&dst as *const libc::sockaddr_in).cast::<libc::sockaddr>(),
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };
        if n != payload.len() as isize {
            return Err(format!("sendto n={n}: {}", std::io::Error::last_os_error()));
        }
        getsockname_v4(fd, "sender getsockname").map_err(|e| e.0)
    });

    let mut buf = [0u8; 100];
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: buf.len(),
    };
    // SAFETY: zeroed structures are filled by recvmsg.
    let mut peer: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = (&mut peer as *mut libc::sockaddr_in).cast();
    msg.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    // SAFETY: `msg` points to valid name and iov storage.
    let n = unsafe { libc::recvmsg(recv.0, &mut msg, 0) };
    if n != 100 {
        return Err(HandlerError(format!(
            "recvmsg n={n}: {} flags={:#x}",
            std::io::Error::last_os_error(),
            msg.msg_flags
        )));
    }
    if msg.msg_flags & libc::MSG_TRUNC == 0 {
        return Err(HandlerError(format!(
            "recvmsg missing MSG_TRUNC: flags={:#x}",
            msg.msg_flags
        )));
    }
    if buf.iter().any(|&b| b != b'x') {
        return Err(HandlerError("truncated payload bytes not preserved".into()));
    }
    let sender_addr = sender
        .join()
        .map_err(|_| HandlerError("sender panicked".into()))?
        .map_err(HandlerError)?;
    let peer_addr = sockaddr_to_v4(peer);
    if peer_addr.port() != sender_addr.port() {
        return Err(HandlerError(format!(
            "peer port {} != sender port {}",
            peer_addr.port(),
            sender_addr.port()
        )));
    }

    Ok(BLOut {
        bound_port: bound.port(),
        peer_port: peer_addr.port(),
        bytes: format!("{} bytes trunc", n),
    })
}

fn dns_probe_server() -> Ipv4Addr {
    std::fs::read_to_string("/etc/resolv.conf")
        .ok()
        .and_then(|content| {
            content.lines().find_map(|line| {
                line.trim()
                    .strip_prefix("nameserver")
                    .and_then(|addr| addr.trim().parse::<Ipv4Addr>().ok())
            })
        })
        .unwrap_or_else(|| Ipv4Addr::new(10, 0, 0, 1))
}

fn raw_dns_probe_for(hostname: &str) -> String {
    let server = dns_probe_server();
    let mut query = vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    for label in hostname.split('.') {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x01]);

    let socket = match UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)) {
        Ok(socket) => socket,
        Err(e) => return format!("bind failed: {e}"),
    };
    if let Err(e) = socket.set_read_timeout(Some(Duration::from_secs(3))) {
        return format!("set_read_timeout failed: {e}");
    }
    if let Err(e) = socket.send_to(&query, (server, 53)) {
        return format!("send_to failed: {e}");
    }
    let mut response = [0u8; 512];
    match socket.recv_from(&mut response) {
        Ok((n, peer)) => {
            let flags = if n >= 4 {
                u16::from_be_bytes([response[2], response[3]])
            } else {
                0
            };
            let answer_count = if n >= 8 {
                u16::from_be_bytes([response[6], response[7]])
            } else {
                0
            };
            format!(
                "ok host={hostname} bytes={n} peer={peer} tc={} answers={answer_count}",
                flags & 0x0200 != 0
            )
        }
        Err(e) => format!("recv_from failed: {e}"),
    }
}

fn raw_dns_probe() -> String {
    raw_dns_probe_for("api.github.com")
}

async fn handle_dns_resolve(_args: (), _ctx: &mut HandlerCtx<'_>) -> Result<DnsOut, HandlerError> {
    let raw_dns = raw_dns_probe();
    if !raw_dns.starts_with("ok ") {
        let resolv_conf = std::fs::read_to_string("/etc/resolv.conf")
            .unwrap_or_else(|e| format!("<read /etc/resolv.conf failed: {e}>"));
        return Err(HandlerError(format!(
            "api.github.com DNS probe failed: {raw_dns}; resolv.conf={resolv_conf:?}"
        )));
    }
    let mut remote_addrs = vec![raw_dns];
    let getaddrinfo_addrs: Vec<String> = ("api.github.com", 443)
        .to_socket_addrs()
        .map_err(|e| HandlerError(format!("getaddrinfo api.github.com: {e}")))?
        .map(|addr| addr.to_string())
        .collect();
    if getaddrinfo_addrs.is_empty() {
        return Err(HandlerError(
            "getaddrinfo api.github.com returned no addresses".into(),
        ));
    }
    remote_addrs.push(format!("getaddrinfo={}", getaddrinfo_addrs.join(",")));

    let localhost_addrs: Vec<String> = ("localhost", 0)
        .to_socket_addrs()
        .map_err(|e| HandlerError(format!("resolve localhost: {e}")))?
        .map(|addr| addr.ip().to_string())
        .collect();
    if !localhost_addrs
        .iter()
        .any(|addr| addr == "127.0.0.1" || addr == "::1")
    {
        return Err(HandlerError(format!(
            "localhost did not resolve to loopback: {localhost_addrs:?}"
        )));
    }

    Ok(DnsOut {
        localhost_addrs,
        remote_addrs,
    })
}

async fn handle_dns_resolve_cname_heavy(
    _args: (),
    _ctx: &mut HandlerCtx<'_>,
) -> Result<DnsOut, HandlerError> {
    let hostnames = [
        "update.code.visualstudio.com",
        "vscode.download.prss.microsoft.com",
        "marketplace.visualstudio.com",
        "vscode-sync.trafficmanager.net",
        "global.rel.tunnels.api.visualstudio.com",
    ];
    let mut remote_addrs = Vec::new();
    for hostname in hostnames {
        let raw_dns = raw_dns_probe_for(hostname);
        if !raw_dns.starts_with("ok ") {
            let resolv_conf = std::fs::read_to_string("/etc/resolv.conf")
                .unwrap_or_else(|e| format!("<read /etc/resolv.conf failed: {e}>"));
            return Err(HandlerError(format!(
                "{hostname} raw DNS probe failed: {raw_dns}; resolv.conf={resolv_conf:?}"
            )));
        }
        remote_addrs.push(raw_dns);

        let addrs: Vec<String> = (hostname, 443)
            .to_socket_addrs()
            .map_err(|e| HandlerError(format!("getaddrinfo {hostname}: {e}")))?
            .map(|addr| addr.to_string())
            .collect();
        if addrs.is_empty() {
            return Err(HandlerError(format!(
                "getaddrinfo {hostname} returned no addresses"
            )));
        }
        remote_addrs.push(format!("{hostname}={}", addrs.join(",")));
    }

    Ok(DnsOut {
        localhost_addrs: Vec::new(),
        remote_addrs,
    })
}

pub(crate) fn register_broker_listener_tests(reg: &mut Registry<'_>) {
    register_handler!(LISTEN_BASIC, handle_listen_basic);
    register_handler!(CONNECT_BASIC, handle_connect_basic);
    register_handler!(UDP_RECVFROM_REMOTE_ADDR, handle_udp_recvfrom_remote_addr);
    register_handler!(UDP_TRUNCATION, handle_udp_truncation);
    register_handler!(RAW_ICMP_ECHO, handle_raw_icmp_echo);
    register_handler!(DNS_RESOLVE, handle_dns_resolve);
    register_handler!(DNS_RESOLVE_CNAME_HEAVY, handle_dns_resolve_cname_heavy);
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
        "udp_recvfrom_remote_addr",
        "BL.udp_recvfrom_remote_addr.pie-glibc.dpg1",
        AgentName::Dpg1,
        &UDP_RECVFROM_REMOTE_ADDR,
        |out| {
            Ok(format!(
                "bound={} peer={} bytes={}",
                out.bound_port, out.peer_port, out.bytes
            ))
        },
    );
    reg.single_agent_handler_test(
        "invariants",
        "udp_truncation",
        "INV.udp_truncation.pie-glibc.dpg1",
        AgentName::Dpg1,
        &UDP_TRUNCATION,
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
        "dns_resolve",
        "BL.dns_resolve.pie-glibc.dpg1",
        AgentName::Dpg1,
        &DNS_RESOLVE,
        |out| {
            Ok(format!(
                "localhost={} remote={}",
                out.localhost_addrs.join(","),
                out.remote_addrs.join(",")
            ))
        },
    );
    reg.single_agent_handler_test(
        "broker_listener",
        "dns_resolve_cname_heavy",
        "BL.dns_resolve_cname_heavy.pie-glibc.dpg1",
        AgentName::Dpg1,
        &DNS_RESOLVE_CNAME_HEAVY,
        |out| Ok(format!("remote={}", out.remote_addrs.join(";"))),
    );
    // Non-default binary legs for the CNAME-heavy resolver path. The
    // pie-glibc leg above passes, but the real VS Code agent-host is the
    // static-pie-musl `code` CLI, and it hangs at startup because musl's
    // resolver (bind a UDP socket, fire parallel A+AAAA at the virtual
    // DNS 10.0.0.1:53) never receives a reply through the broker — see
    // session 05a42e59's audit of `update.code.visualstudio.com`. These
    // legs reproduce that on the gold-standard native baseline (pass) vs
    // litebox (the two musl legs FAIL) until the broker virtual DNS
    // answers musl's query pattern. The glibc non-default legs are
    // controls that isolate "musl resolver" from "non-PIE/static worker".
    for (id, agent) in [
        (
            "BL.dns_resolve_cname_heavy.nonpie-glibc.dpg1_dng",
            AgentName::Dpg1Dng,
        ),
        (
            "BL.dns_resolve_cname_heavy.static-pie-glibc.dpg1_spg",
            AgentName::Dpg1Spg,
        ),
        (
            "BL.dns_resolve_cname_heavy.static-pie-musl.dpg1_spm",
            AgentName::Dpg1Spm,
        ),
        (
            "BL.dns_resolve_cname_heavy.non-pie-static-musl.dpg1_snm",
            AgentName::Dpg1Snm,
        ),
    ] {
        reg.single_agent_handler_test(
            "broker_listener",
            "dns_resolve_cname_heavy",
            id,
            agent,
            &DNS_RESOLVE_CNAME_HEAVY,
            |out| Ok(format!("remote={}", out.remote_addrs.join(";"))),
        );
    }
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
