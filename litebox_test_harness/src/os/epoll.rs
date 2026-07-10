// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Thin idiomatic wrapper over `epoll(7)` for handler bodies.

use std::collections::HashMap;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use crate::protocol::EpollEvent;

#[derive(Clone, Debug)]
pub struct EpollTarget {
    pub kind: &'static str,
    pub id: u64,
}

struct RegisteredFd {
    target: EpollTarget,
    _owned_fd: Option<OwnedFd>,
}

/// Owned epoll file descriptor plus metadata for decoding returned events.
pub struct Epoll {
    fd: OwnedFd,
    registered: HashMap<i32, RegisteredFd>,
}

impl Epoll {
    /// Create an epoll instance with `EPOLL_CLOEXEC`.
    ///
    /// # Errors
    /// Returns the underlying `io::Error` from `epoll_create1(2)`.
    pub fn new() -> Result<Self, std::io::Error> {
        // SAFETY: epoll_create1 creates a fresh descriptor on success.
        let raw = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        if raw < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self {
            // SAFETY: raw is a newly returned descriptor owned by us.
            fd: unsafe { OwnedFd::from_raw_fd(raw) },
            registered: HashMap::new(),
        })
    }

    #[must_use]
    pub fn as_raw_fd(&self) -> i32 {
        self.fd.as_raw_fd()
    }

    /// Open `pidfd_open(pid)` and add it to this epoll set.
    ///
    /// # Errors
    /// Returns an error string for `pidfd_open`, event parsing, or `epoll_ctl` failures.
    pub fn add_pidfd(&mut self, pid: u32, events: &str) -> Result<(), String> {
        let pid_arg =
            libc::pid_t::try_from(pid).map_err(|_| format!("pid {pid} does not fit pid_t"))?;
        // SAFETY: syscall is invoked with pidfd_open's documented arguments
        // (pid, flags=0). On success the returned fd is uniquely owned here.
        let ret = unsafe { libc::syscall(libc::SYS_pidfd_open, pid_arg, 0u32) };
        if ret < 0 {
            return Err(format!(
                "pidfd_open({pid}): {}",
                std::io::Error::last_os_error()
            ));
        }
        let fd =
            i32::try_from(ret).map_err(|_| format!("pidfd_open returned out-of-range fd {ret}"))?;
        // SAFETY: fd was just returned by pidfd_open and is owned here.
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        self.add_raw_fd(
            owned.as_raw_fd(),
            events,
            EpollTarget {
                kind: "pidfd",
                id: u64::from(pid),
            },
            Some(owned),
        )
    }

    /// Add a live raw fd to this epoll set. The caller must keep the fd
    /// alive for at least as long as it remains registered with this `Epoll`.
    ///
    /// # Errors
    /// Returns an error string for event parsing or `epoll_ctl` failures.
    pub fn add_fd(&mut self, fd: i32, events: &str, target: EpollTarget) -> Result<(), String> {
        self.add_raw_fd(fd, events, target, None)
    }

    fn add_raw_fd(
        &mut self,
        fd: i32,
        events: &str,
        target: EpollTarget,
        owned_fd: Option<OwnedFd>,
    ) -> Result<(), String> {
        let mask = parse_events(events)?;
        let token = u64::try_from(fd).map_err(|_| format!("invalid negative fd {fd}"))?;
        let mut event = libc::epoll_event {
            events: mask,
            u64: token,
        };
        // SAFETY: self.fd and fd are live descriptors, and event points
        // to initialized storage for epoll_ctl.
        let rc = unsafe {
            libc::epoll_ctl(self.fd.as_raw_fd(), libc::EPOLL_CTL_ADD, fd, &raw mut event)
        };
        if rc != 0 {
            return Err(format!(
                "epoll_ctl ADD fd {fd}: {}",
                std::io::Error::last_os_error()
            ));
        }
        self.registered.insert(
            fd,
            RegisteredFd {
                target,
                _owned_fd: owned_fd,
            },
        );
        Ok(())
    }

    /// Wait for readiness and decode events using the registered target metadata.
    ///
    /// # Errors
    /// Returns an error string for `epoll_wait` failures or unknown returned tokens.
    pub fn wait(&self, timeout_ms: i32, max_events: u32) -> Result<Vec<EpollEvent>, String> {
        let max_events = max_events.clamp(1, 1024) as usize;
        let mut raw_events = vec![libc::epoll_event { events: 0, u64: 0 }; max_events];
        // SAFETY: raw_events is valid writable storage for max_events
        // entries and self.fd is a live epoll descriptor.
        let max_events_i32 = i32::try_from(max_events)
            .map_err(|_| format!("max_events {max_events} exceeds i32::MAX"))?;
        let n = unsafe {
            libc::epoll_wait(
                self.fd.as_raw_fd(),
                raw_events.as_mut_ptr(),
                max_events_i32,
                timeout_ms,
            )
        };
        if n < 0 {
            return Err(format!("epoll_wait: {}", std::io::Error::last_os_error()));
        }
        let n =
            usize::try_from(n).map_err(|_| format!("epoll_wait returned negative count {n}"))?;
        let mut events = Vec::with_capacity(n);
        for raw in raw_events.into_iter().take(n) {
            let token = raw.u64;
            let fd = i32::try_from(token)
                .map_err(|_| format!("epoll returned out-of-range fd token {token}"))?;
            let Some(registered) = self.registered.get(&fd) else {
                return Err(format!("epoll returned unknown fd token {fd}"));
            };
            events.push(EpollEvent {
                kind: registered.target.kind.to_string(),
                id: registered.target.id,
                observed_events: format_events(raw.events),
            });
        }
        Ok(events)
    }
}

fn parse_events(events: &str) -> Result<u32, String> {
    let mut mask = 0u32;
    for part in events
        .split('|')
        .map(str::trim)
        .filter(|part| !part.is_empty())
    {
        mask |= match part.to_ascii_lowercase().as_str() {
            "in" => libc::EPOLLIN as u32,
            "out" => libc::EPOLLOUT as u32,
            "err" => libc::EPOLLERR as u32,
            "hup" => libc::EPOLLHUP as u32,
            "rdhup" => libc::EPOLLRDHUP as u32,
            "pri" => libc::EPOLLPRI as u32,
            "et" => libc::EPOLLET.cast_unsigned(),
            "oneshot" => libc::EPOLLONESHOT as u32,
            other => return Err(format!("unknown epoll event token {other:?}")),
        };
    }
    if mask == 0 {
        return Err("epoll event mask is empty".to_string());
    }
    Ok(mask)
}

fn format_events(mask: u32) -> String {
    let mut names = Vec::new();
    for (bit, name) in [
        (libc::EPOLLIN as u32, "in"),
        (libc::EPOLLOUT as u32, "out"),
        (libc::EPOLLERR as u32, "err"),
        (libc::EPOLLHUP as u32, "hup"),
        (libc::EPOLLRDHUP as u32, "rdhup"),
        (libc::EPOLLPRI as u32, "pri"),
        (libc::EPOLLET.cast_unsigned(), "et"),
        (libc::EPOLLONESHOT as u32, "oneshot"),
    ] {
        if (mask & bit) != 0 {
            names.push(name);
        }
    }
    if names.is_empty() {
        "none".to_string()
    } else {
        names.join("|")
    }
}
