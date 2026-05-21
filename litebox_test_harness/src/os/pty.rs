// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Thin wrapper over Linux pseudo-terminal operations for handler bodies.

use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::{Duration, Instant};

/// Owned pseudo-terminal master descriptor.
pub struct Pty {
    fd: OwnedFd,
    slave_path: String,
}

impl Pty {
    /// Open a master/slave pseudo-terminal pair using `posix_openpt`,
    /// `grantpt`, `unlockpt`, and `ptsname_r`.
    ///
    /// # Errors
    /// Returns an error string if any underlying libc operation fails.
    pub fn open() -> Result<Self, String> {
        // SAFETY: posix_openpt returns a fresh master fd on success.
        let fd = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(format!("posix_openpt: {}", std::io::Error::last_os_error()));
        }
        // SAFETY: fd is a newly opened descriptor and ownership is transferred.
        let master = unsafe { OwnedFd::from_raw_fd(fd) };
        // SAFETY: grantpt operates on the live pty master fd without taking ownership.
        if unsafe { libc::grantpt(master.as_raw_fd()) } != 0 {
            return Err(format!("grantpt: {}", std::io::Error::last_os_error()));
        }
        // SAFETY: unlockpt operates on the live pty master fd without taking ownership.
        if unsafe { libc::unlockpt(master.as_raw_fd()) } != 0 {
            return Err(format!("unlockpt: {}", std::io::Error::last_os_error()));
        }
        let mut buf = vec![0i8; 128];
        // SAFETY: buf is valid writable storage and master is a live pty master fd.
        let pts_rc = unsafe { libc::ptsname_r(master.as_raw_fd(), buf.as_mut_ptr(), buf.len()) };
        if pts_rc != 0 {
            return Err(format!(
                "ptsname_r: {}",
                std::io::Error::from_raw_os_error(pts_rc)
            ));
        }
        let nul = buf
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| "ptsname_r returned unterminated path".to_string())?;
        let slave_path = String::from_utf8(
            buf[..nul]
                .iter()
                .map(|&b| u8::try_from(b).unwrap_or_default())
                .collect(),
        )
        .map_err(|e| format!("ptsname utf8: {e}"))?;
        set_nonblocking(master.as_raw_fd())?;
        Ok(Self {
            fd: master,
            slave_path,
        })
    }

    /// Return the path to the slave side of the pty.
    #[must_use]
    pub fn slave_path(&self) -> &str {
        &self.slave_path
    }

    /// Return the raw master fd without transferring ownership.
    #[must_use]
    pub fn as_raw_fd(&self) -> i32 {
        self.fd.as_raw_fd()
    }

    /// Fork and exec `args`, wiring fd 0/1/2 to the pty slave. If
    /// `ctrl_tty` is true, make the slave the child session's controlling tty.
    ///
    /// # Errors
    /// Returns an error string for bad args or failed `fork` setup.
    pub fn fork_exec(&self, args: &[String], ctrl_tty: bool) -> Result<libc::pid_t, String> {
        if args.is_empty() {
            return Err("pty exec requires args".to_string());
        }
        let slave_path =
            CString::new(self.slave_path.as_str()).map_err(|e| format!("slave path: {e}"))?;
        let c_args: Vec<CString> = args
            .iter()
            .map(|arg| CString::new(arg.as_str()).map_err(|e| format!("arg contains nul: {e}")))
            .collect::<Result<_, _>>()?;
        let mut exec_argv: Vec<*const libc::c_char> =
            c_args.iter().map(|item| item.as_ptr()).collect();
        exec_argv.push(std::ptr::null());
        let master_fd = self.fd.as_raw_fd();
        // SAFETY: fork creates a child process. The child only calls libc syscalls
        // and execvp before _exit, avoiding Rust destructors after fork.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(format!("fork: {}", std::io::Error::last_os_error()));
        }
        if pid == 0 {
            // SAFETY: child process setup before exec; failures exit immediately.
            unsafe {
                if libc::setsid() < 0 {
                    libc::_exit(126);
                }
                let slave_fd = libc::open(slave_path.as_ptr(), libc::O_RDWR | libc::O_NOCTTY);
                if slave_fd < 0 {
                    libc::_exit(126);
                }
                if ctrl_tty && libc::ioctl(slave_fd, libc::TIOCSCTTY, 0) < 0 {
                    libc::_exit(126);
                }
                for target in 0..=2 {
                    if slave_fd != target && libc::dup3(slave_fd, target, 0) < 0 {
                        libc::_exit(126);
                    }
                }
                if slave_fd > 2 {
                    libc::close(slave_fd);
                }
                libc::close(master_fd);
                libc::execvp(c_args[0].as_ptr(), exec_argv.as_ptr());
                libc::_exit(127);
            }
        }
        Ok(pid)
    }

    /// Write all bytes to the pty master.
    ///
    /// # Errors
    /// Returns an error string if `write(2)` fails permanently.
    pub fn write_all(&self, mut data: &[u8]) -> Result<(), String> {
        while !data.is_empty() {
            // SAFETY: data points to readable memory and fd is a live pty master.
            let n = unsafe { libc::write(self.fd.as_raw_fd(), data.as_ptr().cast(), data.len()) };
            if n < 0 {
                let err = std::io::Error::last_os_error();
                if matches!(err.raw_os_error(), Some(libc::EINTR | libc::EAGAIN)) {
                    continue;
                }
                return Err(format!("pty write fd {}: {err}", self.fd.as_raw_fd()));
            }
            data = &data[n.cast_unsigned()..];
        }
        Ok(())
    }

    /// Read from the pty master. `None` reads until EOF/EIO or a quiet
    /// timeout after data; `Some(n)` reads exactly up to `n` bytes.
    ///
    /// # Errors
    /// Returns an error string on timeout or permanent read/poll failure.
    pub fn read(&self, n_bytes: Option<u32>) -> Result<String, String> {
        let fd = self.fd.as_raw_fd();
        let target = n_bytes.map(|n| n as usize);
        let mut out = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if target.is_some_and(|want| out.len() >= want) {
                break;
            }
            let now = Instant::now();
            if now >= deadline {
                if target.is_none() && !out.is_empty() {
                    break;
                }
                return Err(format!("pty read fd {fd}: timeout"));
            }
            let remaining = deadline.saturating_duration_since(now).as_millis();
            let timeout_ms = i32::try_from(remaining.min(1000)).unwrap_or(1000);
            let mut pollfd = libc::pollfd {
                fd,
                events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
                revents: 0,
            };
            // SAFETY: pollfd points to one valid pollfd entry for this call.
            let ready = unsafe { libc::poll(std::ptr::from_mut(&mut pollfd), 1, timeout_ms) };
            if ready < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(format!("pty poll fd {fd}: {err}"));
            }
            if ready == 0 {
                continue;
            }
            let mut buf = [0u8; 4096];
            let want = target.map_or(buf.len(), |n| (n - out.len()).min(buf.len()));
            // SAFETY: buf is valid writable memory and fd is a live pty master.
            let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), want) };
            if n > 0 {
                out.extend_from_slice(&buf[..n.cast_unsigned()]);
                continue;
            }
            if n == 0 {
                break;
            }
            let err = std::io::Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::EINTR | libc::EAGAIN) => {}
                Some(libc::EIO) if target.is_none() => break,
                _ => return Err(format!("pty read fd {fd}: {err}")),
            }
        }
        Ok(String::from_utf8_lossy(&out).to_string())
    }

    /// Non-blocking read attempt — single `read(2)` with no poll wait.
    /// Returns `Ok(Some(bytes))` if data is available, `Ok(None)` if
    /// EAGAIN/empty, `Err(_)` on permanent failure. EOF (n=0) is
    /// returned as `Ok(Some(empty))`.
    ///
    /// Used by `PTYR.slave_write_atomicity` to verify that after a
    /// child writes to its slave fd and exits (parent has already
    /// reaped the child), the bytes are IMMEDIATELY readable from the
    /// master without any poll/wait latency. This is the invariant
    /// dropbear's session loop relies on; without it, dropbear races
    /// the broker-PTY's slave→master notification and loses the last
    /// writes (Phase H "no output" symptom).
    pub fn try_read_now(&self, max_bytes: usize) -> Result<Option<Vec<u8>>, String> {
        let fd = self.fd.as_raw_fd();
        // SAFETY: fcntl reads the file status flags.
        let saved_flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if saved_flags < 0 {
            return Err(format!(
                "pty fcntl F_GETFL fd {fd}: {}",
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: fcntl sets the file status flags.
        let rc = unsafe { libc::fcntl(fd, libc::F_SETFL, saved_flags | libc::O_NONBLOCK) };
        if rc < 0 {
            return Err(format!(
                "pty fcntl F_SETFL O_NONBLOCK fd {fd}: {}",
                std::io::Error::last_os_error()
            ));
        }
        let mut buf = vec![0u8; max_bytes];
        // SAFETY: buf is writable for at least max_bytes; fd is a live master.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), max_bytes) };
        let read_err = if n < 0 {
            Some(std::io::Error::last_os_error())
        } else {
            None
        };
        // SAFETY: restore prior flag state (best effort).
        let _ = unsafe { libc::fcntl(fd, libc::F_SETFL, saved_flags) };
        if n > 0 {
            #[allow(clippy::cast_sign_loss)]
            buf.truncate(n as usize);
            Ok(Some(buf))
        } else if n == 0 {
            Ok(Some(Vec::new()))
        } else if let Some(err) = read_err {
            match err.raw_os_error() {
                Some(libc::EAGAIN) => Ok(None),
                Some(libc::EIO) => Ok(Some(Vec::new())),
                _ => Err(format!("pty read fd {fd}: {err}")),
            }
        } else {
            Err(format!("pty read fd {fd}: unexpected negative return {n}"))
        }
    }

    /// Resize the pty window.
    ///
    /// # Errors
    /// Returns an error string if `ioctl(TIOCSWINSZ)` fails.
    pub fn resize(&self, rows: u16, cols: u16) -> Result<(), String> {
        let ws = libc::winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: ioctl TIOCSWINSZ reads the provided winsize for a live pty fd.
        if unsafe { libc::ioctl(self.fd.as_raw_fd(), libc::TIOCSWINSZ, &raw const ws) } != 0 {
            return Err(format!(
                "TIOCSWINSZ fd {}: {}",
                self.fd.as_raw_fd(),
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }
}

/// Wait for a child pid returned by [`Pty::fork_exec`]. Kills the child on timeout.
///
/// # Errors
/// Returns an error string if `waitpid(2)` fails or the timeout expires.
pub fn wait_child_timeout(pid: libc::pid_t, timeout: Duration) -> Result<i32, String> {
    let deadline = Instant::now() + timeout;
    let mut status = 0;
    loop {
        // SAFETY: waiting for a child pid returned by fork in this process.
        let rc = unsafe { libc::waitpid(pid, &raw mut status, libc::WNOHANG) };
        if rc == pid {
            if libc::WIFEXITED(status) {
                return Ok(libc::WEXITSTATUS(status));
            }
            if libc::WIFSIGNALED(status) {
                return Ok(128 + libc::WTERMSIG(status));
            }
            return Ok(-1);
        }
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EINTR) {
                return Err(format!("waitpid {pid}: {err}"));
            }
        }
        if Instant::now() >= deadline {
            // SAFETY: pid is a child process previously returned by fork.
            let _ = unsafe { libc::kill(pid, libc::SIGKILL) };
            // SAFETY: reap the child after SIGKILL; errors are reported by timeout below.
            let _ = unsafe { libc::waitpid(pid, &raw mut status, 0) };
            return Err(format!(
                "child {pid} timed out after {}s",
                timeout.as_secs()
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn set_nonblocking(fd: i32) -> Result<(), String> {
    // SAFETY: fcntl(F_GETFL) reads flags from a live fd.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(format!(
            "fcntl getfl fd {fd}: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: fcntl(F_SETFL) updates flags on the same live fd.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } != 0 {
        return Err(format!(
            "fcntl nonblock fd {fd}: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}
