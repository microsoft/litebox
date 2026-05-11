// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Thin idiomatic wrappers over TCP sockets for handler bodies.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

/// Owned TCP socket descriptor.
pub struct TcpSocket {
    fd: OwnedFd,
}

impl TcpSocket {
    /// Create a loopback TCP listener bound to `port` (`0` for ephemeral).
    ///
    /// # Errors
    /// Returns the underlying `io::Error` from socket, bind, listen, or getsockname.
    pub fn new_tcp_listen(port: u16) -> Result<Self, std::io::Error> {
        // SAFETY: socket creates a fresh descriptor on success.
        let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        if raw < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: raw was just returned by socket and is uniquely owned here.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let one: libc::c_int = 1;
        // SAFETY: fd is live; one is valid readable storage for a c_int option value.
        let _ = unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_REUSEADDR,
                std::ptr::from_ref(&one).cast::<libc::c_void>(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        let addr = loopback_addr(port);
        // SAFETY: addr points to a valid IPv4 sockaddr and fd is a live socket.
        let rc = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                std::ptr::from_ref(&addr).cast::<libc::sockaddr>(),
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: fd is a live bound TCP socket; listen does not take ownership.
        let rc = unsafe { libc::listen(fd.as_raw_fd(), 128) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self { fd })
    }

    /// Connect to `127.0.0.1:port`.
    ///
    /// # Errors
    /// Returns the underlying `io::Error` from socket or connect.
    pub fn connect_loopback(port: u16) -> Result<Self, std::io::Error> {
        // SAFETY: socket creates a fresh descriptor on success.
        let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        if raw < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: raw was just returned by socket and is uniquely owned here.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let addr = loopback_addr(port);
        // SAFETY: addr points to a valid IPv4 sockaddr and fd is a live socket.
        let rc = unsafe {
            libc::connect(
                fd.as_raw_fd(),
                std::ptr::from_ref(&addr).cast::<libc::sockaddr>(),
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self { fd })
    }

    /// Accept one inbound connection.
    ///
    /// # Errors
    /// Returns the underlying `io::Error` from accept.
    pub fn accept(&self) -> Result<Self, std::io::Error> {
        loop {
            // SAFETY: self.fd is a live listening socket; null addr ignores peer address.
            let raw = unsafe {
                libc::accept4(
                    self.fd.as_raw_fd(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    libc::SOCK_CLOEXEC,
                )
            };
            if raw >= 0 {
                // SAFETY: raw was just returned by accept4 and is uniquely owned here.
                return Ok(Self {
                    fd: unsafe { OwnedFd::from_raw_fd(raw) },
                });
            }
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EINTR) {
                return Err(err);
            }
        }
    }

    /// Return the local TCP port for this socket.
    ///
    /// # Errors
    /// Returns the underlying `io::Error` from getsockname.
    pub fn local_port(&self) -> Result<u16, std::io::Error> {
        // SAFETY: zeroed sockaddr_in is a valid output buffer for getsockname.
        let mut addr = unsafe { std::mem::zeroed::<libc::sockaddr_in>() };
        let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        // SAFETY: addr and len are valid writable storage; fd is live.
        let rc = unsafe {
            libc::getsockname(
                self.fd.as_raw_fd(),
                std::ptr::from_mut(&mut addr).cast::<libc::sockaddr>(),
                &mut len,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(u16::from_be(addr.sin_port))
    }

    /// Send the entire buffer.
    ///
    /// # Errors
    /// Returns the underlying `io::Error` from send.
    pub fn send_all(&self, mut data: &[u8]) -> Result<(), std::io::Error> {
        while !data.is_empty() {
            // SAFETY: data points to readable memory for data.len() bytes; fd is live.
            let n = unsafe {
                libc::send(
                    self.fd.as_raw_fd(),
                    data.as_ptr().cast::<libc::c_void>(),
                    data.len(),
                    libc::MSG_NOSIGNAL,
                )
            };
            if n > 0 {
                let n = usize::try_from(n).expect("positive send length fits usize");
                data = &data[n..];
                continue;
            }
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EINTR) {
                return Err(err);
            }
        }
        Ok(())
    }

    /// Receive exactly `n_bytes` and decode them as UTF-8-lossy text.
    ///
    /// # Errors
    /// Returns `UnexpectedEof` on early EOF or the underlying recv error.
    pub fn recv_exact_string(&self, n_bytes: usize) -> Result<String, std::io::Error> {
        let mut buf = vec![0_u8; n_bytes];
        let mut filled = 0;
        while filled < n_bytes {
            let n = self.recv_into(&mut buf[filled..])?;
            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    format!("EOF after {filled} of {n_bytes} bytes"),
                ));
            }
            filled += n;
        }
        Ok(String::from_utf8_lossy(&buf).to_string())
    }

    /// Receive until EOF and decode the bytes as UTF-8-lossy text.
    ///
    /// # Errors
    /// Returns the underlying `io::Error` from recv.
    pub fn recv_to_end_string(&self) -> Result<String, std::io::Error> {
        let mut out = Vec::new();
        let mut buf = [0_u8; 4096];
        loop {
            let n = self.recv_into(&mut buf)?;
            if n == 0 {
                return Ok(String::from_utf8_lossy(&out).to_string());
            }
            out.extend_from_slice(&buf[..n]);
        }
    }

    /// Echo bytes from this socket until peer EOF.
    ///
    /// # Errors
    /// Returns the underlying `io::Error` from recv or send.
    pub fn echo_to_eof(&self) -> Result<(), std::io::Error> {
        let mut buf = [0_u8; 4096];
        loop {
            let n = self.recv_into(&mut buf)?;
            if n == 0 {
                return Ok(());
            }
            self.send_all(&buf[..n])?;
        }
    }

    /// Shut down the write half of the socket.
    ///
    /// # Errors
    /// Returns the underlying `io::Error` from shutdown.
    pub fn shutdown_write(&self) -> Result<(), std::io::Error> {
        // SAFETY: fd is live; shutdown does not take ownership.
        let rc = unsafe { libc::shutdown(self.fd.as_raw_fd(), libc::SHUT_WR) };
        if rc == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    fn recv_into(&self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
        loop {
            // SAFETY: buf points to writable memory for buf.len() bytes; fd is live.
            let n = unsafe {
                libc::recv(
                    self.fd.as_raw_fd(),
                    buf.as_mut_ptr().cast::<libc::c_void>(),
                    buf.len(),
                    0,
                )
            };
            if n >= 0 {
                return usize::try_from(n).map_err(|_| std::io::Error::other("negative recv"));
            }
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EINTR) {
                return Err(err);
            }
        }
    }
}

fn loopback_addr(port: u16) -> libc::sockaddr_in {
    libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: port.to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_be(libc::INADDR_LOOPBACK),
        },
        sin_zero: [0; 8],
    }
}
