// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Side-channel timing telemetry for litebox test runs.
//!
//! See `Cargo.toml` for the rationale (PTY contamination via stderr,
//! product-code noise). This crate is intentionally tiny: one env-var
//! check at process startup, one `libc::write` per marker.

use std::os::fd::RawFd;
use std::sync::OnceLock;

/// Result of `init_from_env`: `Some(fd)` if `LITEBOX_TIMING_PATH` was set
/// and we opened it successfully, `None` otherwise.
static FD: OnceLock<Option<RawFd>> = OnceLock::new();

/// Initialize the timing channel from the `LITEBOX_TIMING_PATH` env var.
///
/// Idempotent. Must be called before `emit` to have any effect.
/// If the env var is unset or the open fails, all future `emit` calls
/// are silent no-ops.
///
/// The fd is intentionally never closed: the process keeps it open for
/// its entire lifetime. Markers are written via raw `libc::write` calls
/// (no buffering, async-signal-safe-ish) so each emission is one
/// syscall and reaches disk without flush coordination.
pub fn init_from_env() {
    let _ = FD.get_or_init(open_from_env);
}

fn open_from_env() -> Option<RawFd> {
    let path = std::env::var_os("LITEBOX_TIMING_PATH")?;
    let path_bytes = path.as_encoded_bytes();
    let mut buf = Vec::with_capacity(path_bytes.len() + 1);
    buf.extend_from_slice(path_bytes);
    buf.push(0);
    let flags = libc::O_WRONLY | libc::O_APPEND | libc::O_CREAT | libc::O_CLOEXEC;
    // SAFETY: `buf` is a NUL-terminated C string with valid bytes.
    // `0o644` is the file mode applied iff O_CREAT actually creates the file.
    let fd = unsafe { libc::open(buf.as_ptr().cast(), flags, 0o644) };
    if fd < 0 {
        // Make open() failures visible so the test harness can diagnose
        // bind-mount or env-propagation regressions. This is one-shot per
        // process and reaches the test's stderr log.
        let errno = std::io::Error::last_os_error();
        eprintln!(
            "[litebox_timing] open({:?}) failed: {errno}",
            std::path::Path::new(std::ffi::OsStr::new(&path))
        );
        None
    } else {
        Some(fd)
    }
}

/// Append a `name=<CLOCK_MONOTONIC ns>\n` line to the timing channel.
///
/// If `init_from_env` was not called, or the env var was unset, this is
/// a single predicted-branch no-op (one `OnceLock::get` + nullness
/// check, no syscall).
///
/// Concurrent writers on the same file are safe under Linux O_APPEND
/// semantics provided each write is smaller than `PIPE_BUF` (typically
/// 4096); our lines are far below that.
pub fn emit(name: &str) {
    let Some(Some(fd)) = FD.get() else {
        return;
    };
    let ns = monotonic_nanos();
    let line = format!("{name}={ns}\n");
    let bytes = line.as_bytes();
    // SAFETY: `fd` is owned by this process (opened in `open_from_env`),
    // `bytes` is a valid pointer/length pair, and we ignore short writes
    // because lines are well below `PIPE_BUF` so partial writes are
    // not expected for a regular file under Linux.
    unsafe {
        let _ = libc::write(*fd, bytes.as_ptr().cast(), bytes.len());
    }
}

/// Read `CLOCK_MONOTONIC` in nanoseconds. Available even when the
/// timing channel is disabled, for callers that need to record a
/// boundary timestamp without emission.
pub fn monotonic_nanos() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid out-pointer for `clock_gettime`.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &raw mut ts) };
    if rc == 0 {
        let secs = u64::try_from(ts.tv_sec).unwrap_or(0);
        let nanos = u64::try_from(ts.tv_nsec).unwrap_or(0);
        secs * 1_000_000_000 + nanos
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emit_is_noop_without_env() {
        // Should never panic, regardless of whether `init_from_env`
        // has been called or whether the env var is set.
        emit("noop_test_marker");
    }

    #[test]
    fn monotonic_nanos_monotonic() {
        let a = monotonic_nanos();
        let b = monotonic_nanos();
        assert!(b >= a, "{a} > {b}");
    }
}
