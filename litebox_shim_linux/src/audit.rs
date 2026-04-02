// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Structured audit logging for syscall tracing.
//!
//! When the `audit_log` feature is enabled, every syscall dispatched through the shim is logged
//! as a JSON line via [`DebugLogProvider::debug_log_print`]. This provides a complete, structured
//! audit trail of all guest activity — useful for observability, anomaly detection, and
//! security analysis of LLM agent tool execution.
//!
//! The types here are `no_std`-compatible and avoid heap allocation per event by using
//! fixed-capacity [`arrayvec`] types.

// We intentionally store raw bits of signed values (e.g., status codes, ProtFlags) as u64.
#![allow(clippy::cast_sign_loss)]

use arrayvec::{ArrayString, ArrayVec};
use core::fmt;

/// Maximum number of arguments recorded per syscall event.
const MAX_ARGS: usize = 6;

/// A single argument captured from a syscall invocation.
#[derive(Clone)]
pub enum AuditArg {
    /// A file descriptor number.
    Fd(i32),
    /// A filesystem path (truncated to 256 bytes).
    Path(ArrayString<256>),
    /// A network address string, e.g. `"10.0.0.1:443"` (truncated to 64 bytes).
    Addr(ArrayString<64>),
    /// A generic integer value (flags, sizes, offsets, etc.).
    Int(u64),
    /// A human-readable flag or enum description (truncated to 64 bytes).
    Flags(ArrayString<64>),
}

impl fmt::Display for AuditArg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fd(fd) => write!(f, "{{\"fd\":{fd}}}"),
            Self::Path(p) => {
                write!(f, "{{\"path\":\"")?;
                write_json_escaped(f, p)?;
                write!(f, "\"}}")
            }
            Self::Addr(a) => write!(f, "{{\"addr\":\"{a}\"}}"),
            Self::Int(v) => write!(f, "{{\"int\":{v}}}"),
            Self::Flags(fl) => write!(f, "{{\"flags\":\"{fl}\"}}"),
        }
    }
}

/// A structured audit event emitted for each syscall.
pub struct AuditEvent {
    /// The syscall name (e.g., `"openat"`, `"read"`, `"connect"`).
    pub syscall_name: &'static str,
    /// Parsed arguments from the syscall invocation.
    pub args: ArrayVec<AuditArg, MAX_ARGS>,
    /// The syscall return value: `Ok(value)` or `Err(negated_errno)`.
    pub result: Result<usize, i32>,
}

impl AuditEvent {
    /// Create a new audit event with the given syscall name.
    pub fn new(syscall_name: &'static str) -> Self {
        Self {
            syscall_name,
            args: ArrayVec::new(),
            result: Ok(0),
        }
    }

    /// Record a file descriptor argument.
    pub fn fd(&mut self, fd: i32) -> &mut Self {
        let _ = self.args.try_push(AuditArg::Fd(fd));
        self
    }

    /// Record a path argument, truncating if necessary.
    pub fn path(&mut self, p: &str) -> &mut Self {
        let mut s = ArrayString::<256>::new();
        // Truncate gracefully if the path is too long.
        let _ = s.try_push_str(if p.len() <= 256 { p } else { &p[..256] });
        let _ = self.args.try_push(AuditArg::Path(s));
        self
    }

    /// Record an integer argument.
    pub fn int(&mut self, v: u64) -> &mut Self {
        let _ = self.args.try_push(AuditArg::Int(v));
        self
    }

    /// Record a flags/enum argument.
    pub fn flags(&mut self, f: &str) -> &mut Self {
        let mut s = ArrayString::<64>::new();
        let _ = s.try_push_str(if f.len() <= 64 { f } else { &f[..64] });
        let _ = self.args.try_push(AuditArg::Flags(s));
        self
    }

    /// Set the result of this syscall.
    pub fn set_result(&mut self, r: Result<usize, i32>) -> &mut Self {
        self.result = r;
        self
    }
}

impl fmt::Display for AuditEvent {
    /// Emit the event as a single JSON line.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{{\"syscall\":\"{}\",\"args\":[", self.syscall_name)?;
        for (i, arg) in self.args.iter().enumerate() {
            if i > 0 {
                write!(f, ",")?;
            }
            write!(f, "{arg}")?;
        }
        write!(f, "],\"result\":")?;
        match self.result {
            Ok(v) => write!(f, "{{\"ok\":{v}}}")?,
            Err(e) => write!(f, "{{\"err\":{e}}}")?,
        }
        write!(f, "}}")
    }
}

/// Write a string with JSON-safe escaping (handles `\`, `"`, and control characters).
fn write_json_escaped(f: &mut fmt::Formatter<'_>, s: &str) -> fmt::Result {
    for ch in s.chars() {
        match ch {
            '"' => write!(f, "\\\"")?,
            '\\' => write!(f, "\\\\")?,
            '\n' => write!(f, "\\n")?,
            '\r' => write!(f, "\\r")?,
            '\t' => write!(f, "\\t")?,
            c if c.is_control() => write!(f, "\\u{:04x}", c as u32)?,
            c => write!(f, "{c}")?,
        }
    }
    Ok(())
}

/// Emit an audit event via the platform's debug log.
pub fn emit_audit_event(event: &AuditEvent) {
    use litebox::platform::DebugLogProvider as _;
    let msg = alloc::format!("{event}\n");
    litebox_platform_multiplex::platform().debug_log_print(&msg);
}

/// Build an [`AuditEvent`] from a typed [`SyscallRequest`], extracting human-readable arguments
/// for the most security-relevant syscalls.
pub fn build_audit_event(
    request: &litebox_common_linux::SyscallRequest<litebox_platform_multiplex::Platform>,
) -> AuditEvent {
    use litebox::platform::RawConstPointer as _;
    use litebox_common_linux::SyscallRequest;

    /// Helper: extract a path string from a `RawConstPointer<i8>`, recording it on the event.
    fn record_path(
        ev: &mut AuditEvent,
        ptr: <litebox_platform_multiplex::Platform as litebox::platform::RawPointerProvider>::RawConstPointer<i8>,
    ) {
        if let Some(s) = ptr.to_cstring() {
            ev.path(s.to_str().unwrap_or("<non-utf8>"));
        }
    }

    match request {
        // --- File operations ---
        SyscallRequest::Openat {
            dirfd,
            pathname,
            flags,
            mode,
        } => {
            let mut ev = AuditEvent::new("openat");
            ev.fd(*dirfd);
            record_path(&mut ev, *pathname);
            ev.int(u64::from(flags.bits()));
            ev.int(u64::from(mode.bits()));
            ev
        }
        SyscallRequest::Read { fd, count, .. } => {
            let mut ev = AuditEvent::new("read");
            ev.fd(*fd);
            ev.int(*count as u64);
            ev
        }
        SyscallRequest::Write { fd, count, .. } => {
            let mut ev = AuditEvent::new("write");
            ev.fd(*fd);
            ev.int(*count as u64);
            ev
        }
        SyscallRequest::Close { fd } => {
            let mut ev = AuditEvent::new("close");
            ev.fd(*fd);
            ev
        }
        SyscallRequest::Unlinkat {
            dirfd,
            pathname,
            flags,
        } => {
            let mut ev = AuditEvent::new("unlinkat");
            ev.fd(*dirfd);
            record_path(&mut ev, *pathname);
            ev.int(flags.bits() as u64);
            ev
        }
        SyscallRequest::Mkdir { pathname, mode } => {
            let mut ev = AuditEvent::new("mkdir");
            record_path(&mut ev, *pathname);
            ev.int(u64::from(*mode));
            ev
        }

        // --- Process operations ---
        SyscallRequest::Execve { pathname, .. } => {
            let mut ev = AuditEvent::new("execve");
            record_path(&mut ev, *pathname);
            ev
        }
        SyscallRequest::Exit { status } => {
            let mut ev = AuditEvent::new("exit");
            ev.int(*status as u64);
            ev
        }
        SyscallRequest::ExitGroup { status } => {
            let mut ev = AuditEvent::new("exit_group");
            ev.int(*status as u64);
            ev
        }
        SyscallRequest::Clone { .. } => AuditEvent::new("clone"),
        SyscallRequest::Clone3 { .. } => AuditEvent::new("clone3"),

        // --- Memory operations ---
        SyscallRequest::Mmap {
            addr,
            length,
            prot,
            flags,
            fd,
            ..
        } => {
            let mut ev = AuditEvent::new("mmap");
            ev.int(*addr as u64);
            ev.int(*length as u64);
            ev.int(prot.bits() as u64);
            ev.int(flags.bits() as u64);
            ev.fd(*fd);
            ev
        }
        SyscallRequest::Mprotect { addr, length, prot } => {
            let mut ev = AuditEvent::new("mprotect");
            ev.int(addr.as_usize() as u64);
            ev.int(*length as u64);
            ev.int(prot.bits() as u64);
            ev
        }
        SyscallRequest::Munmap { addr, length } => {
            let mut ev = AuditEvent::new("munmap");
            ev.int(addr.as_usize() as u64);
            ev.int(*length as u64);
            ev
        }
        SyscallRequest::Brk { addr } => {
            let mut ev = AuditEvent::new("brk");
            ev.int(addr.as_usize() as u64);
            ev
        }

        // --- Network operations ---
        SyscallRequest::Socket {
            domain,
            type_and_flags,
            protocol,
        } => {
            let mut ev = AuditEvent::new("socket");
            ev.int(u64::from(*domain));
            ev.int(u64::from(*type_and_flags));
            ev.int(u64::from(*protocol));
            ev
        }
        SyscallRequest::Connect {
            sockfd, addrlen, ..
        } => {
            let mut ev = AuditEvent::new("connect");
            ev.fd(*sockfd);
            ev.int(*addrlen as u64);
            ev
        }
        SyscallRequest::Bind {
            sockfd, addrlen, ..
        } => {
            let mut ev = AuditEvent::new("bind");
            ev.fd(*sockfd);
            ev.int(*addrlen as u64);
            ev
        }
        SyscallRequest::Listen { sockfd, backlog } => {
            let mut ev = AuditEvent::new("listen");
            ev.fd(*sockfd);
            ev.int(u64::from(*backlog));
            ev
        }
        SyscallRequest::Accept { sockfd, flags, .. } => {
            let mut ev = AuditEvent::new("accept");
            ev.fd(*sockfd);
            ev.int(u64::from(flags.bits()));
            ev
        }

        // --- All other syscalls: log the name from Debug repr ---
        other => {
            // Extract the variant name from the Debug representation.
            // `SyscallRequest::Gettid` debugs as "Gettid", `SyscallRequest::Fcntl { fd, arg }`
            // as "Fcntl { ... }". We take the first word as the syscall name.
            let debug_str = alloc::format!("{other:?}");
            let name_end = debug_str.find([' ', '{', '(']).unwrap_or(debug_str.len());
            let name = &debug_str[..name_end];
            let mut ev = AuditEvent::new("other");
            // Store the variant name as a flags argument for visibility.
            ev.flags(name);
            ev
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    extern crate alloc;
    use alloc::format;

    #[test]
    fn audit_event_json_format() {
        let mut event = AuditEvent::new("openat");
        event.fd(-100).path("/etc/passwd").flags("O_RDONLY");
        event.set_result(Ok(3));

        let json = format!("{event}");
        assert!(json.contains("\"syscall\":\"openat\""));
        assert!(json.contains("\"path\":\"/etc/passwd\""));
        assert!(json.contains("\"fd\":-100"));
        assert!(json.contains("\"flags\":\"O_RDONLY\""));
        assert!(json.contains("\"ok\":3"));
    }

    #[test]
    fn audit_event_error_result() {
        let mut event = AuditEvent::new("connect");
        event.fd(5).int(443);
        event.set_result(Err(-13));

        let json = format!("{event}");
        assert!(json.contains("\"err\":-13"));
    }

    #[test]
    fn audit_event_path_escaping() {
        let mut event = AuditEvent::new("openat");
        event.path("/path/with\"quotes");
        event.set_result(Ok(0));

        let json = format!("{event}");
        assert!(json.contains("\\\"quotes"));
    }
}
