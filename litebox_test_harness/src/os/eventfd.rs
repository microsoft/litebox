// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Thin idiomatic wrapper over `eventfd(2)` for handler bodies.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

/// Owned eventfd file descriptor.
pub struct EventFd {
    fd: OwnedFd,
    flags: u32,
}

/// Flags parsed from a `|`-separated string like
/// `"semaphore|nonblock|cloexec"`. Mirrors the legacy
/// `parse_eventfd_flags` in agent.rs so existing tests stay aligned.
///
/// # Errors
/// Returns Err if `flags` contains an unknown token.
pub fn parse_flags(flags: &str) -> Result<u32, String> {
    let mut bits: u32 = 0;
    for token in flags.split('|') {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        let bit: u32 = match token {
            "semaphore" => libc::EFD_SEMAPHORE as u32,
            "nonblock" => libc::EFD_NONBLOCK as u32,
            "cloexec" => libc::EFD_CLOEXEC as u32,
            other => return Err(format!("unknown eventfd flag: {other:?}")),
        };
        bits |= bit;
    }
    Ok(bits)
}

impl EventFd {
    /// `eventfd(initval, flags)`. `flags` is parsed via
    /// [`parse_flags`].
    ///
    /// # Errors
    /// - Bad flag string.
    /// - Underlying `io::Error` from `eventfd(2)`.
    pub fn open(initval: u64, flags: &str) -> Result<Self, std::io::Error> {
        let init = u32::try_from(initval).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("eventfd initval {initval} > u32::MAX"),
            )
        })?;
        let flag_bits = parse_flags(flags)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        // SAFETY: eventfd creates a new fd and does not alias memory.
        let raw = unsafe { libc::eventfd(init, flag_bits.cast_signed()) };
        if raw < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: raw is a newly returned descriptor owned by us.
        Ok(Self {
            fd: unsafe { OwnedFd::from_raw_fd(raw) },
            flags: flag_bits,
        })
    }

    #[must_use]
    pub fn flag_bits(&self) -> u32 {
        self.flags
    }

    #[must_use]
    pub fn as_raw_fd(&self) -> i32 {
        self.fd.as_raw_fd()
    }

    /// Read the eventfd counter. Returns `Err` with "EAGAIN" if no
    /// data is available on a non-blocking fd.
    ///
    /// # Errors
    /// `io::Error` for any non-`EAGAIN` failure; a custom
    /// `WouldBlock` error for EAGAIN.
    pub fn read(&self) -> Result<u64, std::io::Error> {
        let mut value = 0u64;
        loop {
            // SAFETY: value is valid writable storage for 8 bytes.
            let rc = unsafe {
                libc::read(
                    self.fd.as_raw_fd(),
                    std::ptr::from_mut(&mut value).cast::<libc::c_void>(),
                    8,
                )
            };
            if rc == 8 {
                return Ok(value);
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

    /// Write a value to the eventfd counter.
    ///
    /// # Errors
    /// `io::Error` for write failures.
    pub fn write(&self, value: u64) -> Result<(), std::io::Error> {
        loop {
            // SAFETY: value is valid readable storage for 8 bytes.
            let rc = unsafe {
                libc::write(
                    self.fd.as_raw_fd(),
                    std::ptr::from_ref(&value).cast::<libc::c_void>(),
                    8,
                )
            };
            if rc == 8 {
                return Ok(());
            }
            let err = std::io::Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::EINTR) => {}
                _ => return Err(err),
            }
        }
    }

    /// Run the EPOLLET edge-triggered probe used by the legacy
    /// `eventfd_epollet_probe` agent helper. Returns the
    /// `first=N,second=N,value=N,flags=...` detail string the
    /// `run_epollet` test asserts on.
    ///
    /// # Errors
    /// `io::Error` from `epoll_create1`, `epoll_ctl`, or
    /// `epoll_wait`.
    pub fn epollet_probe(&self) -> Result<String, std::io::Error> {
        // SAFETY: epoll_create1 returns a fresh fd on success.
        let raw_ep = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        if raw_ep < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: raw_ep is newly returned and owned by us.
        let epfd = unsafe { OwnedFd::from_raw_fd(raw_ep) };

        let mut ev = libc::epoll_event {
            events: (libc::EPOLLIN | libc::EPOLLET).cast_unsigned(),
            u64: 1,
        };
        // SAFETY: both fds are live; ev is initialized.
        let ctl = unsafe {
            libc::epoll_ctl(
                epfd.as_raw_fd(),
                libc::EPOLL_CTL_ADD,
                self.fd.as_raw_fd(),
                std::ptr::from_mut(&mut ev),
            )
        };
        if ctl != 0 {
            return Err(std::io::Error::last_os_error());
        }

        let mut events = [libc::epoll_event { events: 0, u64: 0 }; 4];
        // SAFETY: events is valid writable storage for 4 entries.
        let first = unsafe { libc::epoll_wait(epfd.as_raw_fd(), events.as_mut_ptr(), 4, 1000) };
        if first < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: same valid storage; timeout 0 is nonblocking.
        let second = unsafe { libc::epoll_wait(epfd.as_raw_fd(), events.as_mut_ptr(), 4, 0) };
        if second < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let value = self.read()?;
        Ok(format!(
            "first={first},second={second},value={value},flags={:#x}",
            self.flags
        ))
    }
}
