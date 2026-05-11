// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Unix-domain socket helpers for handler bodies.

use std::ffi::CString;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::path::PathBuf;

/// Owned connected Unix stream socket.
pub struct UnixStream {
    fd: OwnedFd,
}

/// Owned Unix stream listener. Removes its path on drop.
pub struct UnixListener {
    fd: OwnedFd,
    path: PathBuf,
}

impl UnixListener {
    /// Bind and listen on an `AF_UNIX`/`SOCK_STREAM` socket at `path`.
    ///
    /// # Errors
    /// Returns an error string if any underlying libc call fails.
    pub fn bind(path: &str) -> Result<Self, String> {
        let c_path = sockaddr_path(path)?;
        let _ = std::fs::remove_file(path);
        // SAFETY: socket creates a fresh fd on success.
        let raw = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        if raw < 0 {
            return Err(format!("unix socket: {}", std::io::Error::last_os_error()));
        }
        // SAFETY: raw was just returned by socket and is uniquely owned here.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let (addr, len) = sockaddr_un(&c_path)?;
        // SAFETY: addr points to a valid sockaddr_un and fd is a live Unix socket.
        let rc = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                std::ptr::addr_of!(addr).cast::<libc::sockaddr>(),
                len,
            )
        };
        if rc != 0 {
            return Err(format!(
                "unix bind {path}: {}",
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: fd is a live bound socket; listen does not take ownership.
        if unsafe { libc::listen(fd.as_raw_fd(), 16) } != 0 {
            return Err(format!(
                "unix listen {path}: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(Self {
            fd,
            path: PathBuf::from(path),
        })
    }

    /// Accept one incoming stream connection.
    ///
    /// # Errors
    /// Returns an error string if `accept4(2)` fails.
    pub fn accept(&self) -> Result<UnixStream, String> {
        loop {
            // SAFETY: accept4 operates on the live listener fd and returns a fresh fd on success.
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
                return Ok(UnixStream {
                    fd: unsafe { OwnedFd::from_raw_fd(raw) },
                });
            }
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EINTR) {
                return Err(format!("unix accept {}: {err}", self.path.display()));
            }
        }
    }
}

impl Drop for UnixListener {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

impl UnixStream {
    /// Connect to an `AF_UNIX`/`SOCK_STREAM` listener at `path`.
    ///
    /// # Errors
    /// Returns an error string if socket creation or connect fails.
    pub fn connect(path: &str) -> Result<Self, String> {
        let c_path = sockaddr_path(path)?;
        // SAFETY: socket creates a fresh fd on success.
        let raw = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        if raw < 0 {
            return Err(format!("unix socket: {}", std::io::Error::last_os_error()));
        }
        // SAFETY: raw was just returned by socket and is uniquely owned here.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let (addr, len) = sockaddr_un(&c_path)?;
        // SAFETY: addr points to a valid sockaddr_un and fd is a live Unix socket.
        let rc = unsafe {
            libc::connect(
                fd.as_raw_fd(),
                std::ptr::addr_of!(addr).cast::<libc::sockaddr>(),
                len,
            )
        };
        if rc != 0 {
            return Err(format!(
                "unix connect {path}: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(Self { fd })
    }

    /// Send one fd with `SCM_RIGHTS`.
    ///
    /// # Errors
    /// Returns an error string if `sendmsg(2)` fails.
    pub fn send_fd(&self, fd: BorrowedFd<'_>, payload: &[u8]) -> Result<(), String> {
        self.send_fds(&[fd], payload)
    }

    /// Send one or more fds with `SCM_RIGHTS` and a small payload.
    ///
    /// # Errors
    /// Returns an error string if `sendmsg(2)` fails.
    pub fn send_fds(&self, fds: &[BorrowedFd<'_>], payload: &[u8]) -> Result<(), String> {
        if fds.is_empty() {
            return Err("send_fds requires at least one fd".to_string());
        }
        let raw_fds: Vec<RawFd> = fds.iter().map(AsRawFd::as_raw_fd).collect();
        let mut data = payload.to_vec();
        let mut iov = libc::iovec {
            iov_base: data.as_mut_ptr().cast(),
            iov_len: data.len(),
        };
        let fd_bytes = std::mem::size_of_val(raw_fds.as_slice());
        // SAFETY: CMSG_SPACE only computes the control-buffer size.
        let mut control = vec![0u8; unsafe { libc::CMSG_SPACE(fd_bytes as u32) as usize }];
        // SAFETY: zeroed msghdr is a valid base; fields used below are initialized.
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = std::ptr::addr_of_mut!(iov);
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = control
            .len()
            .try_into()
            .map_err(|_| "sendmsg control buffer length overflow".to_string())?;
        // SAFETY: msg has a control buffer large enough for all raw_fds.
        unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(&msg);
            if cmsg.is_null() {
                return Err("CMSG_FIRSTHDR returned null".to_string());
            }
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = libc::CMSG_LEN(fd_bytes as u32)
                .try_into()
                .map_err(|_| "SCM_RIGHTS cmsg length overflow".to_string())?;
            std::ptr::copy_nonoverlapping(
                raw_fds.as_ptr().cast::<u8>(),
                libc::CMSG_DATA(cmsg).cast::<u8>(),
                fd_bytes,
            );
            msg.msg_controllen = (*cmsg).cmsg_len;
        }
        loop {
            // SAFETY: self.fd is a live Unix stream socket; msg references live buffers.
            let rc = unsafe { libc::sendmsg(self.fd.as_raw_fd(), std::ptr::addr_of!(msg), 0) };
            if rc == data.len() as isize {
                return Ok(());
            }
            if rc >= 0 {
                return Err(format!("sendmsg sent {rc} bytes, expected {}", data.len()));
            }
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EINTR) {
                return Err(format!("sendmsg SCM_RIGHTS: {err}"));
            }
        }
    }

    /// Receive one fd with `SCM_RIGHTS`.
    ///
    /// # Errors
    /// Returns an error string if `recvmsg(2)` fails or no fd is present.
    pub fn recv_fd(&self, max_payload: usize) -> Result<(OwnedFd, Vec<u8>), String> {
        let (mut fds, payload) = self.recv_fds(max_payload, 1)?;
        Ok((fds.remove(0), payload))
    }

    /// Receive one or more fds with `SCM_RIGHTS`.
    ///
    /// # Errors
    /// Returns an error string if `recvmsg(2)` fails or no fds are present.
    pub fn recv_fds(
        &self,
        max_payload: usize,
        max_fds: usize,
    ) -> Result<(Vec<OwnedFd>, Vec<u8>), String> {
        let mut data = vec![0u8; max_payload.max(1)];
        let mut iov = libc::iovec {
            iov_base: data.as_mut_ptr().cast(),
            iov_len: data.len(),
        };
        let fd_bytes = max_fds.max(1) * std::mem::size_of::<RawFd>();
        // SAFETY: CMSG_SPACE only computes the control-buffer size.
        let mut control = vec![0u8; unsafe { libc::CMSG_SPACE(fd_bytes as u32) as usize }];
        // SAFETY: zeroed msghdr is a valid base; fields used below are initialized.
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = std::ptr::addr_of_mut!(iov);
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = control
            .len()
            .try_into()
            .map_err(|_| "recvmsg control buffer length overflow".to_string())?;
        let n = loop {
            // SAFETY: self.fd is live; msg references writable data/control buffers.
            let rc = unsafe {
                libc::recvmsg(
                    self.fd.as_raw_fd(),
                    std::ptr::addr_of_mut!(msg),
                    libc::MSG_CMSG_CLOEXEC,
                )
            };
            if rc >= 0 {
                break rc as usize;
            }
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EINTR) {
                return Err(format!("recvmsg SCM_RIGHTS: {err}"));
            }
        };
        if msg.msg_flags & libc::MSG_CTRUNC != 0 {
            return Err("recvmsg control data truncated".to_string());
        }
        if msg.msg_flags & libc::MSG_TRUNC != 0 {
            return Err("recvmsg payload truncated".to_string());
        }
        // SAFETY: msg's control buffer was initialized by recvmsg.
        let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
        if cmsg.is_null() {
            return Err("recvmsg did not include SCM_RIGHTS cmsg".to_string());
        }
        // SAFETY: cmsg points inside msg's initialized control buffer.
        let (level, kind, len) = unsafe {
            (
                (*cmsg).cmsg_level,
                (*cmsg).cmsg_type,
                (*cmsg).cmsg_len as usize,
            )
        };
        if level != libc::SOL_SOCKET || kind != libc::SCM_RIGHTS {
            return Err(format!("unexpected cmsg level={level} type={kind}"));
        }
        // SAFETY: CMSG_LEN only computes the header length.
        let header_len = unsafe { libc::CMSG_LEN(0) as usize };
        if len < header_len {
            return Err(format!("short cmsg length {len}"));
        }
        let fd_count = (len - header_len) / std::mem::size_of::<RawFd>();
        if fd_count == 0 {
            return Err("SCM_RIGHTS cmsg carried no fds".to_string());
        }
        let mut raw_fds = vec![0; fd_count];
        // SAFETY: CMSG_DATA contains fd_count RawFd values per cmsg length.
        unsafe {
            std::ptr::copy_nonoverlapping(
                libc::CMSG_DATA(cmsg).cast::<RawFd>(),
                raw_fds.as_mut_ptr(),
                fd_count,
            );
        }
        let fds = raw_fds
            .into_iter()
            .map(|fd| {
                // SAFETY: each fd was freshly installed by recvmsg and is uniquely owned.
                unsafe { OwnedFd::from_raw_fd(fd) }
            })
            .collect();
        data.truncate(n);
        Ok((fds, data))
    }
}

fn sockaddr_path(path: &str) -> Result<CString, String> {
    CString::new(path).map_err(|e| format!("unix socket path contains nul: {e}"))
}

fn sockaddr_un(path: &CString) -> Result<(libc::sockaddr_un, libc::socklen_t), String> {
    // SAFETY: zeroed sockaddr_un is a valid base before filling fields.
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let bytes = path.as_bytes_with_nul();
    if bytes.len() > addr.sun_path.len() {
        return Err(format!("unix socket path too long: {} bytes", bytes.len()));
    }
    for (dst, src) in addr.sun_path.iter_mut().zip(bytes) {
        *dst = *src as libc::c_char;
    }
    let len = (std::mem::size_of_val(&addr.sun_family) + bytes.len()) as libc::socklen_t;
    Ok((addr, len))
}
