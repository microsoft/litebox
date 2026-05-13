// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Thin idiomatic wrapper over `signalfd(2)` for handler bodies.
//!
//! Mirrors the shape of [`crate::os::eventfd`]: owned fd, raw +
//! borrowed accessors, and the operations the test scenarios need
//! (`read_siginfo`, `poll_in`).

use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

/// Owned signalfd descriptor.
pub struct Signalfd {
    fd: OwnedFd,
    flags: i32,
}

/// `signalfd_siginfo` subset that scenarios actually inspect.
/// Mirrors the layout in `man signalfd(2)` for the fields we surface;
/// callers wanting the full 128-byte structure can request the raw
/// bytes via [`Signalfd::read_raw`].
#[derive(Debug, Clone, Copy)]
pub struct SiginfoBrief {
    pub ssi_signo: u32,
    pub ssi_errno: i32,
    pub ssi_code: i32,
    pub ssi_pid: u32,
    pub ssi_uid: u32,
}

/// Parse a |-separated signalfd flag string. Supports `nonblock` and
/// `cloexec` to match other `os::*` wrapper conventions.
///
/// # Errors
/// `String` describing the unknown flag token.
pub fn parse_flags(flags: &str) -> Result<i32, String> {
    let mut bits: i32 = 0;
    for token in flags.split('|') {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        let bit: i32 = match token {
            "nonblock" => libc::SFD_NONBLOCK,
            "cloexec" => libc::SFD_CLOEXEC,
            other => return Err(format!("unknown signalfd flag: {other:?}")),
        };
        bits |= bit;
    }
    Ok(bits)
}

impl Signalfd {
    /// `signalfd(-1, &mask, flags)` — create a new signalfd watching
    /// the given signal mask. Caller is responsible for blocking the
    /// signals first with `sigprocmask` so the kernel queues them
    /// onto the signalfd instead of running default handlers.
    ///
    /// # Errors
    /// - Bad flag string.
    /// - `io::Error` from `signalfd(2)`.
    pub fn open(signals: &[i32], flags: &str) -> Result<Self, std::io::Error> {
        let flag_bits = parse_flags(flags)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        // SAFETY: sigset_t is a POD bitmask; zeroed is empty mask.
        let mut mask: libc::sigset_t = unsafe { std::mem::zeroed() };
        // SAFETY: mask is a freshly initialised sigset_t.
        unsafe { libc::sigemptyset(std::ptr::from_mut(&mut mask)) };
        for &signo in signals {
            // SAFETY: mask is a live sigset_t.
            unsafe { libc::sigaddset(std::ptr::from_mut(&mut mask), signo) };
        }
        // SAFETY: signalfd creates a new fd; mask is a live sigset_t.
        let raw = unsafe { libc::signalfd(-1, std::ptr::from_ref(&mask), flag_bits) };
        if raw < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self {
            // SAFETY: raw is a freshly returned owned descriptor.
            fd: unsafe { OwnedFd::from_raw_fd(raw) },
            flags: flag_bits,
        })
    }

    /// Wrap an owned signalfd received via SCM_RIGHTS.
    #[must_use]
    pub fn from_owned_fd(fd: OwnedFd, flags: i32) -> Self {
        Self { fd, flags }
    }

    #[must_use]
    pub fn flag_bits(&self) -> i32 {
        self.flags
    }

    #[must_use]
    pub fn as_raw_fd(&self) -> i32 {
        self.fd.as_raw_fd()
    }

    #[must_use]
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    /// Blocks the given signals in the calling thread's signal mask.
    /// Idempotent. Required before [`Signalfd::open`] so the kernel
    /// queues signals onto the signalfd instead of running default
    /// handlers.
    ///
    /// # Errors
    /// `io::Error` from `pthread_sigmask(3)`.
    pub fn block_signals(signals: &[i32]) -> Result<(), std::io::Error> {
        // SAFETY: sigset_t POD.
        let mut mask: libc::sigset_t = unsafe { std::mem::zeroed() };
        unsafe { libc::sigemptyset(std::ptr::from_mut(&mut mask)) };
        for &signo in signals {
            unsafe { libc::sigaddset(std::ptr::from_mut(&mut mask), signo) };
        }
        // SAFETY: mask is live; SIG_BLOCK is a defined constant.
        let rc = unsafe {
            libc::pthread_sigmask(
                libc::SIG_BLOCK,
                std::ptr::from_ref(&mask),
                std::ptr::null_mut(),
            )
        };
        if rc != 0 {
            return Err(std::io::Error::from_raw_os_error(rc));
        }
        Ok(())
    }

    /// Reads one `signalfd_siginfo` (128 bytes) and parses the fields
    /// scenarios care about. Returns `Err(WouldBlock)` if the fd is
    /// non-blocking and no signal is queued.
    ///
    /// # Errors
    /// `io::Error` for any non-`EAGAIN` failure; a custom
    /// `WouldBlock` error for EAGAIN.
    pub fn read_siginfo(&self) -> Result<SiginfoBrief, std::io::Error> {
        let bytes = self.read_raw()?;
        if bytes.len() < 28 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                format!("short signalfd read: {} bytes", bytes.len()),
            ));
        }
        // signalfd_siginfo layout: u32 ssi_signo, i32 ssi_errno,
        // i32 ssi_code, u32 ssi_pid, u32 ssi_uid (first 20 bytes
        // suffice for our test inspection).
        let ssi_signo = u32::from_ne_bytes(bytes[0..4].try_into().unwrap());
        let ssi_errno = i32::from_ne_bytes(bytes[4..8].try_into().unwrap());
        let ssi_code = i32::from_ne_bytes(bytes[8..12].try_into().unwrap());
        let ssi_pid = u32::from_ne_bytes(bytes[12..16].try_into().unwrap());
        let ssi_uid = u32::from_ne_bytes(bytes[16..20].try_into().unwrap());
        Ok(SiginfoBrief {
            ssi_signo,
            ssi_errno,
            ssi_code,
            ssi_pid,
            ssi_uid,
        })
    }

    /// Reads one raw `signalfd_siginfo` (128-byte) record.
    ///
    /// # Errors
    /// As for [`Self::read_siginfo`].
    pub fn read_raw(&self) -> Result<Vec<u8>, std::io::Error> {
        let mut buf = vec![0u8; 128];
        loop {
            // SAFETY: buf is a live 128-byte buffer.
            let rc = unsafe {
                libc::read(
                    self.fd.as_raw_fd(),
                    buf.as_mut_ptr().cast::<libc::c_void>(),
                    buf.len(),
                )
            };
            if rc > 0 {
                buf.truncate(rc as usize);
                return Ok(buf);
            }
            if rc == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "signalfd read returned 0",
                ));
            }
            let err = std::io::Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::EINTR) => {}
                Some(libc::EAGAIN) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::WouldBlock,
                        "EAGAIN",
                    ));
                }
                _ => return Err(err),
            }
        }
    }

    /// `poll(signalfd, POLLIN, timeout_ms)`. Returns whether a signal
    /// is queued within the timeout.
    ///
    /// # Errors
    /// `io::Error` from `poll(2)`.
    pub fn poll_in(&self, timeout_ms: i32) -> Result<bool, std::io::Error> {
        let mut pfd = libc::pollfd {
            fd: self.fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        loop {
            // SAFETY: pfd is a valid initialised pollfd; len 1 matches.
            let rc = unsafe { libc::poll(std::ptr::from_mut(&mut pfd), 1, timeout_ms) };
            if rc < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(err);
            }
            if rc == 0 {
                return Ok(false);
            }
            return Ok(pfd.revents & libc::POLLIN != 0);
        }
    }
}

impl AsFd for Signalfd {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

impl AsRawFd for Signalfd {
    fn as_raw_fd(&self) -> i32 {
        self.fd.as_raw_fd()
    }
}
