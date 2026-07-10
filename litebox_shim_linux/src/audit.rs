// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Structured audit logging for syscall tracing.
//!
//! When the `audit_log` feature is enabled, every syscall dispatched through the shim is logged
//! as a JSON line. By default, events go to the platform's debug log (typically stderr).
//! Call [`set_audit_log_fd`] before the guest starts to redirect events to a dedicated file
//! descriptor instead, keeping stderr clean for real error messages.

// We intentionally store raw bits of signed values (e.g., status codes, ProtFlags) as u64.
#![allow(clippy::cast_sign_loss)]

use arrayvec::{ArrayString, ArrayVec};
use core::fmt;
use core::sync::atomic::{AtomicI32, AtomicU64, Ordering};

/// File descriptor for the audit log file. When >= 0, audit events are
/// written to this fd instead of stderr. Set via [`set_audit_log_fd`].
static AUDIT_LOG_FD: AtomicI32 = AtomicI32::new(-1);

/// Monotonically increasing sequence number for correlating entry/exit events.
static AUDIT_SEQ: AtomicU64 = AtomicU64::new(0);

/// Host OS PID of this runner process. Disambiguates guest PIDs across
/// fork-restore/worker-exec workers (each has its own host PID).
static WORKER_ID: AtomicI32 = AtomicI32::new(0);

/// Check whether audit logging is active (an fd has been configured).
///
/// Callers use this to skip `build_audit_event` entirely when logging
/// is disabled, avoiding the argument extraction overhead.
#[inline]
pub fn is_enabled() -> bool {
    AUDIT_LOG_FD.load(Ordering::Relaxed) >= 0
}

/// Redirect audit events to the given host file descriptor.
///
/// Call this before the guest starts. The fd must be a valid host-side file
/// descriptor opened for writing (e.g., via `open` with `O_WRONLY | O_CREAT | O_APPEND`).
/// The caller is responsible for keeping the fd open for the lifetime of the sandbox.
pub fn set_audit_log_fd(fd: i32) {
    AUDIT_LOG_FD.store(fd, Ordering::Release);
}

/// Set the worker ID (host OS PID) for this runner process.
/// Called by the runner before the guest starts.
pub fn set_worker_id(id: i32) {
    WORKER_ID.store(id, Ordering::Release);
}

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
    /// Virtual PID of the process that made the syscall.
    pub pid: i32,
    /// Virtual TID of the thread that made the syscall.
    pub tid: i32,
    /// Command name of the process (from execve, e.g., "node", "bash").
    pub comm: ArrayString<16>,
}

impl AuditEvent {
    /// Create a new audit event with the given syscall name.
    pub fn new(syscall_name: &'static str) -> Self {
        Self {
            syscall_name,
            args: ArrayVec::new(),
            result: Ok(0),
            pid: 0,
            tid: 0,
            comm: ArrayString::new(),
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
        write!(
            f,
            "{{\"syscall\":\"{}\",\"pid\":{},\"comm\":\"",
            self.syscall_name, self.pid
        )?;
        write_json_escaped(f, self.comm.as_str())?;
        write!(f, "\",\"args\":[")?;
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

/// Emit an audit event.
///
/// If [`set_audit_log_fd`] was called, writes the JSON line to that file
/// descriptor. Otherwise falls back to the platform's debug log (stderr).
pub fn emit_audit_event(event: &AuditEvent) {
    let msg = alloc::format!("{event}\n");
    write_audit_line(&msg);
}

/// Get monotonic nanoseconds for timestamping audit events.
/// Uses a raw syscall to avoid going through the platform trait (no_std safe).
fn monotonic_nanos() -> u64 {
    #[repr(C)]
    struct Timespec {
        tv_sec: i64,
        tv_nsec: i64,
    }
    let mut ts = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // CLOCK_MONOTONIC = 1
    let _ = unsafe {
        syscalls::syscall2(
            syscalls::Sysno::clock_gettime,
            1,
            core::ptr::addr_of_mut!(ts) as usize,
        )
    };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

/// Return the current host thread ID for audit correlation.
fn host_tid() -> u32 {
    // SAFETY: gettid takes no arguments and has no memory-safety preconditions.
    unsafe { syscalls::raw::syscall0(syscalls::Sysno::gettid) as u32 }
}

/// Allocate a new sequence number and emit the entry (pre-syscall) event.
///
/// Returns the sequence number for pairing with the exit event.
pub fn emit_entry_event(event: &AuditEvent) -> u64 {
    let fd = AUDIT_LOG_FD.load(Ordering::Relaxed);
    if fd < 0 {
        return 0;
    }
    let seq = AUDIT_SEQ.fetch_add(1, Ordering::Relaxed);
    let worker = WORKER_ID.load(Ordering::Relaxed);
    let host_tid = host_tid();
    let ts = monotonic_nanos();
    let mut buf = ArrayString::<512>::new();
    use core::fmt::Write;
    let fit = write!(
        &mut buf,
        "{{\"phase\":\"enter\",\"ts\":{ts},\"seq\":{seq},\"pid\":{},\"tid\":{},\"worker\":{worker},\"host_tid\":{host_tid},\"syscall\":\"{}\",\"args\":[{}]}}\n",
        event.pid,
        event.tid,
        event.syscall_name,
        FormatArgs(&event.args),
    )
    .is_ok();
    if fit {
        write_audit_line_to_fd(fd, buf.as_str());
    } else {
        let msg = alloc::format!(
            "{{\"phase\":\"enter\",\"ts\":{ts},\"seq\":{seq},\"pid\":{},\"tid\":{},\"worker\":{worker},\"host_tid\":{host_tid},\"syscall\":\"{}\",\"args\":[{}]}}\n",
            event.pid,
            event.tid,
            event.syscall_name,
            FormatArgs(&event.args),
        );
        write_audit_line_to_fd(fd, &msg);
    }
    seq
}

/// Emit the exit (post-syscall) event with the result.
pub fn emit_exit_event(
    syscall_name: &str,
    seq: u64,
    pid: i32,
    tid: i32,
    result: Result<usize, i32>,
) {
    let fd = AUDIT_LOG_FD.load(Ordering::Relaxed);
    if fd < 0 {
        return;
    }
    let worker = WORKER_ID.load(Ordering::Relaxed);
    let host_tid = host_tid();
    let ts = monotonic_nanos();
    let mut buf = ArrayString::<256>::new();
    use core::fmt::Write;
    let fit = match result {
        Ok(v) => write!(
            &mut buf,
            "{{\"phase\":\"exit\",\"ts\":{ts},\"seq\":{seq},\"pid\":{pid},\"tid\":{tid},\"worker\":{worker},\"host_tid\":{host_tid},\"syscall\":\"{syscall_name}\",\"result\":{{\"ok\":{v}}}}}\n",
        ),
        Err(e) => write!(
            &mut buf,
            "{{\"phase\":\"exit\",\"ts\":{ts},\"seq\":{seq},\"pid\":{pid},\"tid\":{tid},\"worker\":{worker},\"host_tid\":{host_tid},\"syscall\":\"{syscall_name}\",\"result\":{{\"err\":{e}}}}}\n",
        ),
    }
    .is_ok();
    if fit {
        write_audit_line_to_fd(fd, buf.as_str());
    } else {
        let result_str = match result {
            Ok(v) => alloc::format!("{{\"ok\":{v}}}"),
            Err(e) => alloc::format!("{{\"err\":{e}}}"),
        };
        let msg = alloc::format!(
            "{{\"phase\":\"exit\",\"ts\":{ts},\"seq\":{seq},\"pid\":{pid},\"tid\":{tid},\"worker\":{worker},\"host_tid\":{host_tid},\"syscall\":\"{syscall_name}\",\"result\":{result_str}}}\n",
        );
        write_audit_line_to_fd(fd, &msg);
    }
}

/// Write a line directly to the given audit log fd.
fn write_audit_line_to_fd(fd: i32, msg: &str) {
    use litebox::platform::DebugLogProvider as _;
    litebox_platform_multiplex::platform().debug_log_write_to_fd(fd, msg);
}

/// Write a line to the audit log fd. If no fd was configured via
/// [`set_audit_log_fd`], the event is silently dropped.
fn write_audit_line(msg: &str) {
    let fd = AUDIT_LOG_FD.load(Ordering::Relaxed);
    if fd >= 0 {
        write_audit_line_to_fd(fd, msg);
    }
}

/// Helper for formatting args in the entry event.
struct FormatArgs<'a>(&'a ArrayVec<AuditArg, MAX_ARGS>);

impl fmt::Display for FormatArgs<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, arg) in self.0.iter().enumerate() {
            if i > 0 {
                write!(f, ",")?;
            }
            write!(f, "{arg}")?;
        }
        Ok(())
    }
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

    fn record_clone_args(ev: &mut AuditEvent, args: &litebox_common_linux::CloneArgs) {
        ev.int(args.flags.bits());
        ev.int(args.pidfd);
        ev.int(args.child_tid);
        ev.int(args.parent_tid);
        ev.int(args.exit_signal);
        ev.int(args.stack);
        ev.int(args.stack_size);
        ev.int(args.tls);
        ev.int(args.set_tid);
        ev.int(args.set_tid_size);
        ev.int(args.cgroup);
    }

    // Canonical syscall name is determined exhaustively up-front so that even
    // variants we don't unpack arguments for still get the right name (instead
    // of falling through to a generic "other" bucket).
    let name = syscall_canonical_name(request);

    // reason: large syscall enum; uninteresting audit events intentionally use the canonical fallback.
    #[allow(clippy::wildcard_enum_match_arm)]
    match request {
        // --- File operations ---
        SyscallRequest::Openat {
            dirfd,
            pathname,
            flags,
            mode,
        } => {
            let mut ev = AuditEvent::new(name);
            ev.fd(*dirfd);
            record_path(&mut ev, *pathname);
            ev.int(u64::from(flags.bits()));
            ev.int(u64::from(mode.bits()));
            ev
        }
        SyscallRequest::Read { fd, count, .. } => {
            let mut ev = AuditEvent::new(name);
            ev.fd(*fd);
            ev.int(*count as u64);
            ev
        }
        SyscallRequest::Write { fd, count, .. } => {
            let mut ev = AuditEvent::new(name);
            ev.fd(*fd);
            ev.int(*count as u64);
            ev
        }
        SyscallRequest::Close { fd } => {
            let mut ev = AuditEvent::new(name);
            ev.fd(*fd);
            ev
        }
        SyscallRequest::Lseek { fd, offset, whence } => {
            let mut ev = AuditEvent::new(name);
            ev.fd(*fd);
            ev.int(*offset as u64);
            ev.int(*whence as u64);
            ev
        }
        SyscallRequest::Pread64 {
            fd, count, offset, ..
        }
        | SyscallRequest::Pwrite64 {
            fd, count, offset, ..
        } => {
            let mut ev = AuditEvent::new(name);
            ev.fd(*fd);
            ev.int(*count as u64);
            ev.int(*offset as u64);
            ev
        }
        SyscallRequest::Readv { fd, iovcnt, .. } | SyscallRequest::Writev { fd, iovcnt, .. } => {
            let mut ev = AuditEvent::new(name);
            ev.fd(*fd);
            ev.int(*iovcnt as u64);
            ev
        }
        SyscallRequest::Unlinkat {
            dirfd,
            pathname,
            flags,
        } => {
            let mut ev = AuditEvent::new(name);
            ev.fd(*dirfd);
            record_path(&mut ev, *pathname);
            ev.int(flags.bits() as u64);
            ev
        }
        SyscallRequest::Mkdir { pathname, mode } => {
            let mut ev = AuditEvent::new(name);
            record_path(&mut ev, *pathname);
            ev.int(u64::from(*mode));
            ev
        }
        SyscallRequest::Mkdirat {
            dirfd,
            pathname,
            mode,
        } => {
            let mut ev = AuditEvent::new(name);
            ev.fd(*dirfd);
            record_path(&mut ev, *pathname);
            ev.int(u64::from(*mode));
            ev
        }
        SyscallRequest::Chdir { pathname } => {
            let mut ev = AuditEvent::new(name);
            record_path(&mut ev, *pathname);
            ev
        }
        SyscallRequest::Fchdir { fd } => {
            let mut ev = AuditEvent::new(name);
            ev.fd(*fd);
            ev
        }
        SyscallRequest::Renameat2 {
            olddirfd,
            oldpath,
            newdirfd,
            newpath,
            flags,
        } => {
            let mut ev = AuditEvent::new(name);
            ev.fd(*olddirfd);
            record_path(&mut ev, *oldpath);
            ev.fd(*newdirfd);
            record_path(&mut ev, *newpath);
            ev.int(u64::from(*flags));
            ev
        }
        SyscallRequest::Symlinkat {
            target,
            newdirfd,
            linkpath,
        } => {
            let mut ev = AuditEvent::new(name);
            record_path(&mut ev, *target);
            ev.fd(*newdirfd);
            record_path(&mut ev, *linkpath);
            ev
        }
        SyscallRequest::Linkat {
            olddirfd,
            oldpath,
            newdirfd,
            newpath,
            flags,
        } => {
            let mut ev = AuditEvent::new(name);
            ev.fd(*olddirfd);
            record_path(&mut ev, *oldpath);
            ev.fd(*newdirfd);
            record_path(&mut ev, *newpath);
            ev.int(flags.bits() as u64);
            ev
        }
        SyscallRequest::Fchmod { fd, mode } => {
            let mut ev = AuditEvent::new(name);
            ev.fd(*fd);
            ev.int(u64::from(*mode));
            ev
        }
        SyscallRequest::Fchmodat {
            dirfd,
            pathname,
            mode,
        } => {
            let mut ev = AuditEvent::new(name);
            ev.fd(*dirfd);
            record_path(&mut ev, *pathname);
            ev.int(u64::from(*mode));
            ev
        }
        SyscallRequest::Ftruncate { fd, length } => {
            let mut ev = AuditEvent::new(name);
            ev.fd(*fd);
            ev.int(*length as u64);
            ev
        }
        SyscallRequest::Fsync { fd } | SyscallRequest::Fdatasync { fd } => {
            let mut ev = AuditEvent::new(name);
            ev.fd(*fd);
            ev
        }
        SyscallRequest::Readlink { pathname, .. } => {
            let mut ev = AuditEvent::new(name);
            record_path(&mut ev, *pathname);
            ev
        }
        SyscallRequest::Readlinkat {
            dirfd, pathname, ..
        } => {
            let mut ev = AuditEvent::new(name);
            ev.fd(*dirfd);
            record_path(&mut ev, *pathname);
            ev
        }
        SyscallRequest::Access { pathname, mode } => {
            let mut ev = AuditEvent::new(name);
            record_path(&mut ev, *pathname);
            ev.int(mode.bits() as u64);
            ev
        }
        SyscallRequest::Faccessat {
            dirfd,
            pathname,
            mode,
        } => {
            let mut ev = AuditEvent::new(name);
            ev.fd(*dirfd);
            record_path(&mut ev, *pathname);
            ev.int(mode.bits() as u64);
            ev
        }
        SyscallRequest::Faccessat2 {
            dirfd,
            pathname,
            mode,
            flags,
        } => {
            let mut ev = AuditEvent::new(name);
            ev.fd(*dirfd);
            record_path(&mut ev, *pathname);
            ev.int(mode.bits() as u64);
            ev.int(flags.bits() as u64);
            ev
        }
        SyscallRequest::Stat { pathname, .. } | SyscallRequest::Lstat { pathname, .. } => {
            let mut ev = AuditEvent::new(name);
            record_path(&mut ev, *pathname);
            ev
        }
        SyscallRequest::Statx {
            dirfd,
            pathname,
            flags,
            mask,
            ..
        } => {
            let mut ev = AuditEvent::new(name);
            ev.fd(*dirfd);
            record_path(&mut ev, *pathname);
            ev.int(flags.bits() as u64);
            ev.int(u64::from(*mask));
            ev
        }
        SyscallRequest::Statfs { pathname, .. } => {
            let mut ev = AuditEvent::new(name);
            record_path(&mut ev, *pathname);
            ev
        }
        SyscallRequest::Fstatfs { fd, .. } => {
            let mut ev = AuditEvent::new(name);
            ev.fd(*fd);
            ev
        }
        SyscallRequest::Fadvise64 {
            fd,
            offset,
            len,
            advice,
        } => {
            let mut ev = AuditEvent::new(name);
            ev.fd(*fd);
            ev.int(*offset as u64);
            ev.int(*len as u64);
            ev.int(*advice as u64);
            ev
        }
        SyscallRequest::Sendfile {
            out_fd,
            in_fd,
            count,
            ..
        } => {
            let mut ev = AuditEvent::new(name);
            ev.fd(*out_fd);
            ev.fd(*in_fd);
            ev.int(*count as u64);
            ev
        }
        SyscallRequest::CopyFileRange {
            fd_in,
            fd_out,
            len,
            flags,
            ..
        } => {
            let mut ev = AuditEvent::new(name);
            ev.fd(*fd_in);
            ev.fd(*fd_out);
            ev.int(*len as u64);
            ev.int(u64::from(*flags));
            ev
        }
        SyscallRequest::GetDirent64 { fd, count, .. } => {
            let mut ev = AuditEvent::new(name);
            ev.fd(*fd);
            ev.int(*count as u64);
            ev
        }
        SyscallRequest::Flock { fd, operation } => {
            let mut ev = AuditEvent::new(name);
            ev.fd(*fd);
            ev.int(*operation as u64);
            ev
        }
        SyscallRequest::Fallocate {
            fd,
            mode,
            offset,
            len,
        } => {
            let mut ev = AuditEvent::new(name);
            ev.fd(*fd);
            ev.int(*mode as u64);
            ev.int(*offset as u64);
            ev.int(*len as u64);
            ev
        }

        // --- Xattr operations ---
        SyscallRequest::XattrGetPath {
            pathname,
            name: xname,
            ..
        }
        | SyscallRequest::XattrSetPath {
            pathname,
            name: xname,
            ..
        } => {
            let mut ev = AuditEvent::new(name);
            record_path(&mut ev, *pathname);
            record_path(&mut ev, *xname);
            ev
        }
        SyscallRequest::XattrListPath { pathname, .. } => {
            let mut ev = AuditEvent::new(name);
            record_path(&mut ev, *pathname);
            ev
        }
        SyscallRequest::XattrGetFd {
            fd, name: xname, ..
        }
        | SyscallRequest::XattrSetFd {
            fd, name: xname, ..
        } => {
            let mut ev = AuditEvent::new(name);
            ev.fd(*fd);
            record_path(&mut ev, *xname);
            ev
        }
        SyscallRequest::XattrListFd { fd } => {
            let mut ev = AuditEvent::new(name);
            ev.fd(*fd);
            ev
        }

        // --- Process / signal operations ---
        SyscallRequest::Execve { pathname, .. } => {
            let mut ev = AuditEvent::new(name);
            record_path(&mut ev, *pathname);
            ev
        }
        SyscallRequest::Execveat {
            dirfd,
            pathname,
            flags,
            ..
        } => {
            let mut ev = AuditEvent::new(name);
            ev.fd(*dirfd);
            record_path(&mut ev, *pathname);
            ev.int(*flags as u64);
            ev
        }
        SyscallRequest::Exit { status } | SyscallRequest::ExitGroup { status } => {
            let mut ev = AuditEvent::new(name);
            ev.int(*status as u64);
            ev
        }
        SyscallRequest::Clone { args } => {
            let mut ev = AuditEvent::new(name);
            record_clone_args(&mut ev, args);
            ev
        }
        SyscallRequest::Clone3 { args } => {
            let mut ev = AuditEvent::new(name);
            ev.int(args.as_usize() as u64);
            if let Some(args) = args.read_at_offset(0) {
                record_clone_args(&mut ev, &args);
            }
            ev
        }
        SyscallRequest::Kill { pid, sig } => {
            let mut ev = AuditEvent::new(name);
            ev.int(*pid as u64);
            ev.int(*sig as u64);
            ev
        }
        SyscallRequest::Tkill { tid, sig } => {
            let mut ev = AuditEvent::new(name);
            ev.int(*tid as u64);
            ev.int(*sig as u64);
            ev
        }
        SyscallRequest::Tgkill { tgid, tid, sig } => {
            let mut ev = AuditEvent::new(name);
            ev.int(*tgid as u64);
            ev.int(*tid as u64);
            ev.int(*sig as u64);
            ev
        }
        SyscallRequest::RtSigaction { signum, .. } => {
            let mut ev = AuditEvent::new(name);
            let debug_str = alloc::format!("{signum:?}");
            let name_end = debug_str.find([' ', '(']).unwrap_or(debug_str.len());
            ev.flags(&debug_str[..name_end]);
            ev
        }
        SyscallRequest::RtSigprocmask { how, .. } => {
            let mut ev = AuditEvent::new(name);
            let debug_str = alloc::format!("{how:?}");
            let name_end = debug_str.find([' ', '(']).unwrap_or(debug_str.len());
            ev.flags(&debug_str[..name_end]);
            ev
        }
        SyscallRequest::Wait4 { pid, options, .. } => {
            let mut ev = AuditEvent::new(name);
            ev.int(*pid as u64);
            ev.int(*options as u64);
            ev
        }
        SyscallRequest::Waitid {
            idtype,
            id,
            options,
            ..
        } => {
            let mut ev = AuditEvent::new(name);
            ev.int(u64::from(*idtype));
            ev.int(u64::from(*id));
            ev.int(*options as u64);
            ev
        }
        SyscallRequest::PidfdOpen { pid, flags } => {
            let mut ev = AuditEvent::new(name);
            ev.int(*pid as u64);
            ev.int(u64::from(*flags));
            ev
        }
        SyscallRequest::PidfdSendSignal {
            pidfd, sig, flags, ..
        } => {
            let mut ev = AuditEvent::new(name);
            ev.int(*pidfd as u64);
            ev.int(*sig as u64);
            ev.int(u64::from(*flags));
            ev
        }
        SyscallRequest::Setpgid { pid, pgid } => {
            let mut ev = AuditEvent::new(name);
            ev.int(*pid as u64);
            ev.int(*pgid as u64);
            ev
        }
        SyscallRequest::Getpgid { pid } | SyscallRequest::Getsid { pid } => {
            let mut ev = AuditEvent::new(name);
            ev.int(*pid as u64);
            ev
        }
        SyscallRequest::Futex { args } => {
            let mut ev = AuditEvent::new(name);
            let debug_str = alloc::format!("{args:?}");
            let name_end = debug_str.find([' ', '{', '(']).unwrap_or(debug_str.len());
            ev.flags(&debug_str[..name_end]);
            ev
        }

        // --- Memory operations ---
        SyscallRequest::Mmap {
            addr,
            length,
            prot,
            flags,
            fd,
            ..
        } => {
            let mut ev = AuditEvent::new(name);
            ev.int(*addr as u64);
            ev.int(*length as u64);
            ev.int(prot.bits() as u64);
            ev.int(flags.bits() as u64);
            ev.fd(*fd);
            ev
        }
        SyscallRequest::Mprotect { addr, length, prot } => {
            let mut ev = AuditEvent::new(name);
            ev.int(addr.as_usize() as u64);
            ev.int(*length as u64);
            ev.int(prot.bits() as u64);
            ev
        }
        SyscallRequest::Munmap { addr, length } => {
            let mut ev = AuditEvent::new(name);
            ev.int(addr.as_usize() as u64);
            ev.int(*length as u64);
            ev
        }
        SyscallRequest::Brk { addr } => {
            let mut ev = AuditEvent::new(name);
            ev.int(addr.as_usize() as u64);
            ev
        }
        SyscallRequest::Madvise {
            addr,
            length,
            behavior,
        } => {
            let mut ev = AuditEvent::new(name);
            ev.int(addr.as_usize() as u64);
            ev.int(*length as u64);
            let debug_str = alloc::format!("{behavior:?}");
            let name_end = debug_str.find([' ', '(']).unwrap_or(debug_str.len());
            ev.flags(&debug_str[..name_end]);
            ev
        }

        // --- Network operations ---
        SyscallRequest::Socket {
            domain,
            type_and_flags,
            protocol,
        } => {
            let mut ev = AuditEvent::new(name);
            ev.int(u64::from(*domain));
            ev.int(u64::from(*type_and_flags));
            ev.int(u64::from(*protocol));
            ev
        }
        SyscallRequest::Socketpair {
            domain,
            type_and_flags,
            protocol,
            ..
        } => {
            let mut ev = AuditEvent::new(name);
            ev.int(u64::from(*domain));
            ev.int(u64::from(*type_and_flags));
            ev.int(u64::from(*protocol));
            ev
        }
        SyscallRequest::Connect {
            sockfd,
            sockaddr,
            addrlen,
        } => {
            let mut ev = AuditEvent::new(name);
            ev.fd(*sockfd);
            // Try to parse sockaddr_in for AF_INET to emit dst_ip and dst_port.
            if *addrlen >= 8 {
                // Read the address family (first 2 bytes).
                let family_bytes: Option<[u8; 2]> = sockaddr
                    .read_at_offset(0)
                    .and_then(|b0: u8| sockaddr.read_at_offset(1).map(|b1: u8| [b0, b1]));
                if let Some(fam) = family_bytes {
                    let family = u16::from_ne_bytes(fam);
                    if family == 2 {
                        // AF_INET: port at offset 2 (big-endian), IP at offset 4.
                        let port_hi: u8 = sockaddr.read_at_offset(2).unwrap_or(0);
                        let port_lo: u8 = sockaddr.read_at_offset(3).unwrap_or(0);
                        let port = u16::from_be_bytes([port_hi, port_lo]);
                        let ip0: u8 = sockaddr.read_at_offset(4).unwrap_or(0);
                        let ip1: u8 = sockaddr.read_at_offset(5).unwrap_or(0);
                        let ip2: u8 = sockaddr.read_at_offset(6).unwrap_or(0);
                        let ip3: u8 = sockaddr.read_at_offset(7).unwrap_or(0);
                        let mut addr_str = ArrayString::<64>::new();
                        let _ = core::fmt::write(
                            &mut addr_str,
                            format_args!("{ip0}.{ip1}.{ip2}.{ip3}:{port}"),
                        );
                        ev.args.push(AuditArg::Addr(addr_str));
                    } else {
                        ev.int(*addrlen as u64);
                    }
                } else {
                    ev.int(*addrlen as u64);
                }
            } else {
                ev.int(*addrlen as u64);
            }
            ev
        }
        SyscallRequest::Bind {
            sockfd, addrlen, ..
        } => {
            let mut ev = AuditEvent::new(name);
            ev.fd(*sockfd);
            ev.int(*addrlen as u64);
            ev
        }
        SyscallRequest::Listen { sockfd, backlog } => {
            let mut ev = AuditEvent::new(name);
            ev.fd(*sockfd);
            ev.int(u64::from(*backlog));
            ev
        }
        SyscallRequest::Accept { sockfd, flags, .. } => {
            let mut ev = AuditEvent::new(name);
            ev.fd(*sockfd);
            ev.int(u64::from(flags.bits()));
            ev
        }
        SyscallRequest::Sendto {
            sockfd, len, flags, ..
        } => {
            let mut ev = AuditEvent::new(name);
            ev.fd(*sockfd);
            ev.int(*len as u64);
            ev.int(u64::from(flags.bits()));
            ev
        }
        SyscallRequest::Recvfrom {
            sockfd, len, flags, ..
        } => {
            let mut ev = AuditEvent::new(name);
            ev.fd(*sockfd);
            ev.int(*len as u64);
            ev.int(u64::from(flags.bits()));
            ev
        }
        SyscallRequest::Sendmsg { sockfd, flags, .. } => {
            let mut ev = AuditEvent::new(name);
            ev.fd(*sockfd);
            ev.int(u64::from(flags.bits()));
            ev
        }
        SyscallRequest::Recvmsg { sockfd, flags, .. } => {
            let mut ev = AuditEvent::new(name);
            ev.fd(*sockfd);
            ev.int(u64::from(flags.bits()));
            ev
        }
        SyscallRequest::Sendmmsg {
            sockfd,
            vlen,
            flags,
            ..
        } => {
            let mut ev = AuditEvent::new(name);
            ev.fd(*sockfd);
            ev.int(u64::from(*vlen));
            ev.int(u64::from(flags.bits()));
            ev
        }
        SyscallRequest::Shutdown { sockfd, how } => {
            let mut ev = AuditEvent::new(name);
            ev.fd(*sockfd);
            ev.int(*how as u64);
            ev
        }
        SyscallRequest::Setsockopt {
            sockfd,
            level,
            optname,
            optlen,
            ..
        } => {
            let mut ev = AuditEvent::new(name);
            ev.fd(*sockfd);
            ev.int(u64::from(*level));
            ev.int(u64::from(*optname));
            ev.int(*optlen as u64);
            ev
        }

        // Special case: Ioctl — record fd and command type.
        SyscallRequest::Ioctl { fd, arg } => {
            let mut ev = AuditEvent::new(name);
            ev.fd(*fd);
            let debug_str = alloc::format!("{arg:?}");
            let name_end = debug_str.find([' ', '(']).unwrap_or(debug_str.len());
            ev.flags(&debug_str[..name_end]);
            ev
        }

        // --- fd-bearing syscalls that need explicit logging ---
        SyscallRequest::Fstat { fd, .. } => {
            let mut ev = AuditEvent::new(name);
            ev.fd(*fd);
            ev
        }
        SyscallRequest::Newfstatat {
            dirfd, pathname, ..
        } => {
            let mut ev = AuditEvent::new(name);
            ev.fd(*dirfd);
            record_path(&mut ev, *pathname);
            ev
        }
        SyscallRequest::Fcntl { fd, arg } => {
            let mut ev = AuditEvent::new(name);
            ev.fd(*fd);
            let debug_str = alloc::format!("{arg:?}");
            let name_end = debug_str.find([' ', '(']).unwrap_or(debug_str.len());
            ev.flags(&debug_str[..name_end]);
            ev
        }
        SyscallRequest::EpollCtl { epfd, op, fd, .. } => {
            let mut ev = AuditEvent::new(name);
            ev.fd(*epfd);
            ev.int(*fd as u64);
            let debug_str = alloc::format!("{op:?}");
            let name_end = debug_str.find([' ', '(']).unwrap_or(debug_str.len());
            ev.flags(&debug_str[..name_end]);
            ev
        }
        SyscallRequest::EpollCreate { flags, .. } => {
            let mut ev = AuditEvent::new(name);
            ev.int(u64::from(flags.bits()));
            ev
        }
        SyscallRequest::EpollPwait { epfd, timeout, .. } => {
            let mut ev = AuditEvent::new(name);
            ev.fd(*epfd);
            // timeout is a TimeParam which isn't directly castable
            let debug_str = alloc::format!("{timeout:?}");
            ev.flags(&debug_str);
            ev
        }
        SyscallRequest::Ppoll { nfds, timeout, .. } => {
            let mut ev = AuditEvent::new(name);
            ev.int(*nfds as u64);
            let debug_str = alloc::format!("{timeout:?}");
            ev.flags(&debug_str);
            ev
        }
        SyscallRequest::Pselect { nfds, timeout, .. } => {
            let mut ev = AuditEvent::new(name);
            ev.int(u64::from(*nfds));
            let debug_str = alloc::format!("{timeout:?}");
            ev.flags(&debug_str);
            ev
        }
        SyscallRequest::Getsockopt {
            sockfd,
            level,
            optname,
            ..
        } => {
            let mut ev = AuditEvent::new(name);
            ev.fd(*sockfd);
            ev.int(u64::from(*level));
            ev.int(u64::from(*optname));
            ev
        }
        SyscallRequest::Getsockname { sockfd, .. } => {
            let mut ev = AuditEvent::new(name);
            ev.fd(*sockfd);
            ev
        }
        SyscallRequest::Getpeername { sockfd, .. } => {
            let mut ev = AuditEvent::new(name);
            ev.fd(*sockfd);
            ev
        }
        SyscallRequest::Dup { oldfd, .. } => {
            let mut ev = AuditEvent::new(name);
            ev.fd(*oldfd);
            ev
        }
        SyscallRequest::Pipe2 { flags, .. } => {
            let mut ev = AuditEvent::new(name);
            ev.int(flags.bits() as u64);
            ev
        }

        // --- Eventfd / memfd / timerfd / inotify / signalfd-style fds ---
        SyscallRequest::Eventfd2 { initval, flags } => {
            let mut ev = AuditEvent::new(name);
            ev.int(u64::from(*initval));
            ev.int(u64::from(flags.bits()));
            ev
        }
        SyscallRequest::MemfdCreate { name: mname, flags } => {
            let mut ev = AuditEvent::new(name);
            record_path(&mut ev, *mname);
            ev.int(u64::from(flags.bits()));
            ev
        }
        SyscallRequest::InotifyInit1 { flags } => {
            let mut ev = AuditEvent::new(name);
            ev.int(u64::from(flags.bits()));
            ev
        }
        SyscallRequest::InotifyAddWatch { fd, pathname, mask } => {
            let mut ev = AuditEvent::new(name);
            ev.fd(*fd);
            record_path(&mut ev, *pathname);
            ev.int(u64::from(*mask));
            ev
        }
        SyscallRequest::InotifyRmWatch { fd, wd } => {
            let mut ev = AuditEvent::new(name);
            ev.fd(*fd);
            ev.int(*wd as u64);
            ev
        }
        SyscallRequest::TimerfdCreate { clockid, flags } => {
            let mut ev = AuditEvent::new(name);
            ev.int(*clockid as u64);
            ev.int(u64::from(flags.bits()));
            ev
        }
        SyscallRequest::TimerfdSettime { fd, flags, .. } => {
            let mut ev = AuditEvent::new(name);
            ev.fd(*fd);
            ev.int(u64::from(flags.bits()));
            ev
        }
        SyscallRequest::TimerfdGettime { fd, .. } => {
            let mut ev = AuditEvent::new(name);
            ev.fd(*fd);
            ev
        }

        // --- Clocks / time ---
        SyscallRequest::ClockGettime { clockid, .. }
        | SyscallRequest::ClockGetres { clockid, .. } => {
            let mut ev = AuditEvent::new(name);
            ev.int(*clockid as u64);
            ev
        }
        SyscallRequest::ClockNanosleep { clockid, flags, .. } => {
            let mut ev = AuditEvent::new(name);
            ev.int(*clockid as u64);
            ev.int(flags.bits() as u64);
            ev
        }

        // --- POSIX timers ---
        SyscallRequest::TimerCreate { clockid, .. } => {
            let mut ev = AuditEvent::new(name);
            ev.int(*clockid as u64);
            ev
        }
        SyscallRequest::TimerSettime { timerid, flags, .. } => {
            let mut ev = AuditEvent::new(name);
            ev.int(*timerid as u64);
            ev.int(*flags as u64);
            ev
        }
        SyscallRequest::TimerGettime { timerid, .. }
        | SyscallRequest::TimerDelete { timerid }
        | SyscallRequest::TimerGetoverrun { timerid } => {
            let mut ev = AuditEvent::new(name);
            ev.int(*timerid as u64);
            ev
        }

        // --- Misc with useful args ---
        SyscallRequest::Prctl { args } => {
            let mut ev = AuditEvent::new(name);
            let debug_str = alloc::format!("{args:?}");
            let name_end = debug_str.find([' ', '{', '(']).unwrap_or(debug_str.len());
            ev.flags(&debug_str[..name_end]);
            ev
        }
        SyscallRequest::Prlimit { pid, resource, .. } => {
            let mut ev = AuditEvent::new(name);
            ev.int(*pid as u64);
            let debug_str = alloc::format!("{resource:?}");
            let name_end = debug_str.find([' ', '(']).unwrap_or(debug_str.len());
            ev.flags(&debug_str[..name_end]);
            ev
        }
        SyscallRequest::Getrlimit { resource, .. } | SyscallRequest::Setrlimit { resource, .. } => {
            let mut ev = AuditEvent::new(name);
            let debug_str = alloc::format!("{resource:?}");
            let name_end = debug_str.find([' ', '(']).unwrap_or(debug_str.len());
            ev.flags(&debug_str[..name_end]);
            ev
        }
        SyscallRequest::Umask { mask } => {
            let mut ev = AuditEvent::new(name);
            ev.int(u64::from(*mask));
            ev
        }
        SyscallRequest::Alarm { seconds } => {
            let mut ev = AuditEvent::new(name);
            ev.int(u64::from(*seconds));
            ev
        }
        SyscallRequest::GetRandom { count, flags, .. } => {
            let mut ev = AuditEvent::new(name);
            ev.int(*count as u64);
            ev.int(flags.bits() as u64);
            ev
        }

        // All remaining variants get the canonical name with no args.
        // (The catch-all is reached only for variants that don't carry
        // particularly useful arguments for audit-log analysis; they still
        // get correctly named instead of bucketed under "other".)
        _ => AuditEvent::new(name),
    }
}

/// Map a [`SyscallRequest`] variant to its canonical snake_case Linux syscall
/// name. This is the single source of truth for the `"syscall"` field in audit
/// log entries — every variant must have a name, and the match is exhaustive
/// (no `_` wildcard) so the compiler enforces that newly added
/// `SyscallRequest` variants pick a canonical name before they can be merged.
///
/// Names follow the Linux man-page convention (snake_case, e.g. `eventfd2`,
/// `memfd_create`, `rt_sigprocmask`, `pidfd_open`). Variants that share a
/// canonical name (e.g. `Stat` and `Lstat` both backing `stat` family calls)
/// keep distinct names so they stay distinguishable in the log.
pub fn syscall_canonical_name(
    request: &litebox_common_linux::SyscallRequest<litebox_platform_multiplex::Platform>,
) -> &'static str {
    use litebox_common_linux::SyscallRequest as S;
    match request {
        S::Exit { .. } => "exit",
        S::ExitGroup { .. } => "exit_group",
        S::Read { .. } => "read",
        S::Write { .. } => "write",
        S::Lseek { .. } => "lseek",
        S::Close { .. } => "close",
        S::Stat { .. } => "stat",
        S::Fstat { .. } => "fstat",
        S::Lstat { .. } => "lstat",
        S::Mkdir { .. } => "mkdir",
        S::Mkdirat { .. } => "mkdirat",
        S::Chdir { .. } => "chdir",
        S::Fchdir { .. } => "fchdir",
        S::Mmap { .. } => "mmap",
        S::Mprotect { .. } => "mprotect",
        S::Msync { .. } => "msync",
        S::Munmap { .. } => "munmap",
        S::Mremap { .. } => "mremap",
        S::Brk { .. } => "brk",
        S::RtSigprocmask { .. } => "rt_sigprocmask",
        S::RtSigaction { .. } => "rt_sigaction",
        S::RtSigreturn => "rt_sigreturn",
        #[cfg(target_arch = "x86")]
        S::Sigreturn => "sigreturn",
        S::Kill { .. } => "kill",
        S::Tkill { .. } => "tkill",
        S::Tgkill { .. } => "tgkill",
        S::Sigaltstack { .. } => "sigaltstack",
        S::RtSigsuspend { .. } => "rt_sigsuspend",
        S::RtSigtimedwait { .. } => "rt_sigtimedwait",
        S::Sigpending { .. } => "rt_sigpending",
        S::Ioctl { .. } => "ioctl",
        S::Pread64 { .. } => "pread64",
        S::Pwrite64 { .. } => "pwrite64",
        S::Readv { .. } => "readv",
        S::Writev { .. } => "writev",
        S::Access { .. } => "access",
        S::Faccessat { .. } => "faccessat",
        S::Faccessat2 { .. } => "faccessat2",
        S::Madvise { .. } => "madvise",
        S::Dup { .. } => "dup",
        S::Socket { .. } => "socket",
        #[cfg(target_arch = "x86")]
        S::Socketcall { .. } => "socketcall",
        S::Socketpair { .. } => "socketpair",
        S::Connect { .. } => "connect",
        S::Accept { .. } => "accept",
        S::Sendto { .. } => "sendto",
        S::Sendmsg { .. } => "sendmsg",
        S::Sendmmsg { .. } => "sendmmsg",
        S::Recvfrom { .. } => "recvfrom",
        S::Recvmsg { .. } => "recvmsg",
        S::Bind { .. } => "bind",
        S::Listen { .. } => "listen",
        S::Shutdown { .. } => "shutdown",
        S::Setsockopt { .. } => "setsockopt",
        S::Getsockopt { .. } => "getsockopt",
        S::Getsockname { .. } => "getsockname",
        S::Getpeername { .. } => "getpeername",
        S::Uname { .. } => "uname",
        S::Fcntl { .. } => "fcntl",
        S::Getcwd { .. } => "getcwd",
        S::EpollCtl { .. } => "epoll_ctl",
        S::EpollPwait { .. } => "epoll_pwait",
        S::EpollCreate { .. } => "epoll_create1",
        S::Ppoll { .. } => "ppoll",
        S::Pselect { .. } => "pselect6",
        S::ArchPrctl { .. } => "arch_prctl",
        S::Readlink { .. } => "readlink",
        S::Readlinkat { .. } => "readlinkat",
        S::Openat { .. } => "openat",
        S::Ftruncate { .. } => "ftruncate",
        S::Unlinkat { .. } => "unlinkat",
        S::Renameat2 { .. } => "renameat2",
        S::Symlinkat { .. } => "symlinkat",
        S::Linkat { .. } => "linkat",
        S::Fchmod { .. } => "fchmod",
        S::Fchown => "fchown",
        S::Fchownat => "fchownat",
        S::Fsync { .. } => "fsync",
        S::Fdatasync { .. } => "fdatasync",
        S::Utimensat { .. } => "utimensat",
        S::Seccomp => "seccomp",
        S::Fchmodat { .. } => "fchmodat",
        #[cfg(target_arch = "x86_64")]
        S::Newfstatat { .. } => "newfstatat",
        #[cfg(target_arch = "x86")]
        S::Fstatat64 { .. } => "fstatat64",
        S::Statx { .. } => "statx",
        S::Statfs { .. } => "statfs",
        S::Fstatfs { .. } => "fstatfs",
        S::Fadvise64 { .. } => "fadvise64",
        S::Sendfile { .. } => "sendfile",
        S::CopyFileRange { .. } => "copy_file_range",
        S::Eventfd2 { .. } => "eventfd2",
        S::MemfdCreate { .. } => "memfd_create",
        S::InotifyInit1 { .. } => "inotify_init1",
        S::InotifyAddWatch { .. } => "inotify_add_watch",
        S::InotifyRmWatch { .. } => "inotify_rm_watch",
        S::TimerfdCreate { .. } => "timerfd_create",
        S::TimerfdSettime { .. } => "timerfd_settime",
        S::TimerfdGettime { .. } => "timerfd_gettime",
        S::Flock { .. } => "flock",
        S::Fallocate { .. } => "fallocate",
        S::XattrGetPath { .. } => "getxattr",
        S::XattrSetPath { .. } => "setxattr",
        S::XattrListPath { .. } => "listxattr",
        S::XattrGetFd { .. } => "fgetxattr",
        S::XattrSetFd { .. } => "fsetxattr",
        S::XattrListFd { .. } => "flistxattr",
        S::Pipe2 { .. } => "pipe2",
        S::Clone { .. } => "clone",
        S::Clone3 { .. } => "clone3",
        S::SetThreadArea { .. } => "set_thread_area",
        S::ClockGettime { .. } => "clock_gettime",
        S::ClockGetres { .. } => "clock_getres",
        S::ClockNanosleep { .. } => "clock_nanosleep",
        S::Gettimeofday { .. } => "gettimeofday",
        S::Time { .. } => "time",
        S::Getrusage { .. } => "getrusage",
        S::Getrlimit { .. } => "getrlimit",
        S::Setrlimit { .. } => "setrlimit",
        S::Prlimit { .. } => "prlimit64",
        S::SetTidAddress { .. } => "set_tid_address",
        S::Gettid => "gettid",
        S::SetRobustList { .. } => "set_robust_list",
        S::GetRobustList { .. } => "get_robust_list",
        S::Rseq { .. } => "rseq",
        S::GetRandom { .. } => "getrandom",
        S::Getpid => "getpid",
        S::Getppid => "getppid",
        S::Getpgid { .. } => "getpgid",
        S::Setpgid { .. } => "setpgid",
        S::Getsid { .. } => "getsid",
        S::Setsid => "setsid",
        S::Getuid => "getuid",
        S::Geteuid => "geteuid",
        S::Getgid => "getgid",
        S::Getegid => "getegid",
        S::Getgroups { .. } => "getgroups",
        S::Sysinfo { .. } => "sysinfo",
        S::CapGet { .. } => "capget",
        S::GetDirent64 { .. } => "getdents64",
        S::SchedGetAffinity { .. } => "sched_getaffinity",
        S::SchedYield => "sched_yield",
        S::SchedGetparam { .. } => "sched_getparam",
        S::SchedGetscheduler { .. } => "sched_getscheduler",
        S::SchedSetscheduler { .. } => "sched_setscheduler",
        S::Futex { .. } => "futex",
        S::Execve { .. } => "execve",
        S::Execveat { .. } => "execveat",
        S::Umask { .. } => "umask",
        S::Prctl { .. } => "prctl",
        S::Alarm { .. } => "alarm",
        S::SetITimer { .. } => "setitimer",
        S::TimerCreate { .. } => "timer_create",
        S::TimerSettime { .. } => "timer_settime",
        S::TimerGettime { .. } => "timer_gettime",
        S::TimerDelete { .. } => "timer_delete",
        S::TimerGetoverrun { .. } => "timer_getoverrun",
        S::Wait4 { .. } => "wait4",
        S::Waitid { .. } => "waitid",
        S::ProcessVmReadv { .. } => "process_vm_readv",
        S::PidfdOpen { .. } => "pidfd_open",
        S::PidfdSendSignal { .. } => "pidfd_send_signal",
        // `SyscallRequest` is `#[non_exhaustive]`, so the compiler requires a
        // wildcard. Any newly added variant should add an explicit arm above
        // before the variant is wired through the dispatcher; until then it
        // shows up as `"unknown"` rather than silently being mis-named.
        _ => "unknown",
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

    #[test]
    fn canonical_name_uses_snake_case_for_variants_that_used_to_be_other() {
        use litebox_common_linux::EfdFlags;
        use litebox_common_linux::SyscallRequest as S;
        type P = litebox_platform_multiplex::Platform;

        // Spot-check a handful of variants that previously fell through to
        // the `"other"` catch-all. Each must report its canonical snake_case
        // Linux name — not `"other"`, not CamelCase.
        let req: S<P> = S::Eventfd2 {
            initval: 1,
            flags: EfdFlags::empty(),
        };
        assert_eq!(syscall_canonical_name(&req), "eventfd2");

        let req: S<P> = S::PidfdOpen { pid: 1, flags: 0 };
        assert_eq!(syscall_canonical_name(&req), "pidfd_open");

        let req: S<P> = S::Kill { pid: 1, sig: 9 };
        assert_eq!(syscall_canonical_name(&req), "kill");

        let req: S<P> = S::Tgkill {
            tgid: 1,
            tid: 2,
            sig: 9,
        };
        assert_eq!(syscall_canonical_name(&req), "tgkill");

        let req: S<P> = S::Gettid;
        assert_eq!(syscall_canonical_name(&req), "gettid");

        let req: S<P> = S::Exit { status: 0 };
        assert_eq!(syscall_canonical_name(&req), "exit");

        let req: S<P> = S::Setsid;
        assert_eq!(syscall_canonical_name(&req), "setsid");
    }

    #[test]
    fn build_audit_event_names_eventfd2_correctly_and_records_args() {
        use litebox_common_linux::EfdFlags;
        use litebox_common_linux::SyscallRequest as S;
        type P = litebox_platform_multiplex::Platform;

        let req: S<P> = S::Eventfd2 {
            initval: 7,
            flags: EfdFlags::empty(),
        };
        let ev = build_audit_event(&req);
        let json = format!("{ev}");
        assert!(
            json.contains("\"syscall\":\"eventfd2\""),
            "expected canonical name, got: {json}"
        );
        assert!(
            !json.contains("\"syscall\":\"other\""),
            "must not fall through to `other`: {json}"
        );
        // initval was 7
        assert!(json.contains("\"int\":7"), "json was: {json}");
    }

    #[test]
    fn build_audit_event_records_kill_pid_and_sig() {
        use litebox_common_linux::SyscallRequest as S;
        type P = litebox_platform_multiplex::Platform;

        let req: S<P> = S::Kill { pid: 42, sig: 15 };
        let ev = build_audit_event(&req);
        let json = format!("{ev}");
        assert!(json.contains("\"syscall\":\"kill\""), "{json}");
        assert!(json.contains("\"int\":42"), "{json}");
        assert!(json.contains("\"int\":15"), "{json}");
    }

    #[test]
    fn build_audit_event_never_emits_other_for_no_arg_variants() {
        use litebox_common_linux::SyscallRequest as S;
        type P = litebox_platform_multiplex::Platform;

        // These variants don't have explicit arg handlers in `build_audit_event`
        // and previously would have been bucketed as `"syscall":"other"`.
        // The canonical-name path means they must now be named correctly.
        let cases: &[(S<P>, &str)] = &[
            (S::Gettid, "gettid"),
            (S::Getpid, "getpid"),
            (S::Getppid, "getppid"),
            (S::Getuid, "getuid"),
            (S::Getegid, "getegid"),
            (S::Setsid, "setsid"),
            (S::SchedYield, "sched_yield"),
        ];
        for (req, expected) in cases {
            let ev = build_audit_event(req);
            let json = format!("{ev}");
            assert!(
                json.contains(&format!("\"syscall\":\"{expected}\"")),
                "expected `{expected}`, got: {json}"
            );
            assert!(
                !json.contains("\"syscall\":\"other\""),
                "must not fall through to `other`: {json}"
            );
        }
    }
}
