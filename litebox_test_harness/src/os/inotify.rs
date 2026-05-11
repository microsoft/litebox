// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Thin idiomatic wrapper over `inotify(7)` for handler bodies.
//!
//! ```ignore
//! let ino = Inotify::new()?;
//! let wd = ino.add_watch("/tmp/x", libc::IN_CREATE | libc::IN_MODIFY)?;
//! ctx.checkpoint("armed").await?;
//! let events = ino.drain(Duration::from_secs(2))?;
//! ```

use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// One `inotify_event` returned by `Inotify::drain`. Field names
/// mirror the kernel struct.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Event {
    pub wd: i32,
    pub mask: u32,
    pub cookie: u32,
    pub name: Option<String>,
}

impl Event {
    /// Convenience: check whether `mask` contains a specific bit
    /// (e.g. `libc::IN_CREATE`).
    #[must_use]
    pub fn has(&self, bit: u32) -> bool {
        self.mask & bit != 0
    }
}

/// Owned inotify fd opened with `IN_CLOEXEC | IN_NONBLOCK`. Drop
/// closes the fd.
pub struct Inotify {
    fd: OwnedFd,
}

impl Inotify {
    /// `inotify_init1(IN_CLOEXEC | IN_NONBLOCK)`.
    ///
    /// # Errors
    /// Underlying `io::Error` from `inotify_init1`.
    pub fn new() -> Result<Self, std::io::Error> {
        // SAFETY: inotify_init1 returns a fresh fd not aliased.
        let raw = unsafe { libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK) };
        if raw < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: raw was just returned and is uniquely owned.
        Ok(Self {
            fd: unsafe { OwnedFd::from_raw_fd(raw) },
        })
    }

    /// `inotify_add_watch(self, path, mask)`. Returns the watch
    /// descriptor.
    ///
    /// # Errors
    /// - `InvalidInput` if `path` contains a NUL byte.
    /// - Otherwise, `io::Error` from `inotify_add_watch`.
    pub fn add_watch(&self, path: &str, mask: u32) -> Result<i32, std::io::Error> {
        let path_c = CString::new(path)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in path"))?;
        // SAFETY: path_c is a valid C string; self.fd is live.
        let wd = unsafe { libc::inotify_add_watch(self.fd.as_raw_fd(), path_c.as_ptr(), mask) };
        if wd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(wd)
    }

    /// Block up to `timeout` waiting for events, then drain them in
    /// one `read`. At most 64 events per call.
    ///
    /// # Errors
    /// `io::Error` from underlying `poll` or `read`.
    pub fn drain(&self, timeout: Duration) -> Result<Vec<Event>, std::io::Error> {
        let raw_fd = self.fd.as_raw_fd();
        let timeout_ms = i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX);

        let mut pollfd = libc::pollfd {
            fd: raw_fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let pollfd_ptr: *mut libc::pollfd = std::ptr::from_mut(&mut pollfd);
        // SAFETY: pollfd is one initialized entry.
        let ready = unsafe { libc::poll(pollfd_ptr, 1, timeout_ms) };
        if ready < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if ready == 0 {
            return Ok(Vec::new());
        }

        let event_size = std::mem::size_of::<libc::inotify_event>();
        let mut buf = vec![0u8; 64 * (event_size + libc::NAME_MAX as usize + 1)];
        // SAFETY: buf is valid writable storage; raw_fd is live.
        let n = unsafe { libc::read(raw_fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let n_usize =
            usize::try_from(n).map_err(|_| std::io::Error::other("read returned negative"))?;
        parse_events(&buf[..n_usize])
    }
}

fn parse_events(bytes: &[u8]) -> Result<Vec<Event>, std::io::Error> {
    let mut events = Vec::new();
    let event_size = std::mem::size_of::<libc::inotify_event>();
    let mut offset = 0usize;
    while offset + event_size <= bytes.len() && events.len() < 64 {
        // SAFETY: bounds-checked above; read_unaligned tolerates
        // any alignment.
        let raw_evt = unsafe {
            std::ptr::read_unaligned(bytes.as_ptr().add(offset).cast::<libc::inotify_event>())
        };
        offset += event_size;
        let name_len = raw_evt.len as usize;
        if offset + name_len > bytes.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "short inotify event name",
            ));
        }
        let name = if name_len == 0 {
            None
        } else {
            let raw_name = &bytes[offset..offset + name_len];
            let nul = raw_name
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(raw_name.len());
            Some(String::from_utf8_lossy(&raw_name[..nul]).to_string())
        };
        offset += name_len;
        events.push(Event {
            wd: raw_evt.wd,
            mask: raw_evt.mask,
            cookie: raw_evt.cookie,
            name,
        });
    }
    Ok(events)
}
