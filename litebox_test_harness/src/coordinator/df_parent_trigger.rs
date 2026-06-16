// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! DF_PARENT_TRIGGER: parent-side fd-state × commit_delayed_fork matrix.
//!
//! This family complements the existing `XDF.*` delayed-fork matrix
//! (see [`super::fork_matrix`]) which varies the *child-side* trigger
//! (mmap vs. thread, target binary, invocation form). Here we instead
//! pin the trigger to a minimal mmap and **vary the parent-side
//! fd-state** that is visible in the snapshot examined by
//! `commit_delayed_fork`
//! (`litebox_shim_linux/src/syscalls/process.rs:5891-5917`).
//!
//! Reject set (forces fall-through to vfork shared-AS):
//!   `NetworkSocket | Epoll | TimerFd | PidFd | AnonSpecialFd
//!   | Inotify | Other`.
//! Accept set (snapshot migration succeeds):
//!   `StdioFd | Pipe | FilesystemFd | UnixSocket | EventFd | Signalfd
//!   | InetListener`.
//!
//! Shape per test:
//!   1. The leaf agent (its binary type is `parent_bt`) opens one fd
//!      of the requested `parent_fd_class` and keeps it open.
//!   2. The leaf `fork+exec`s a child binary of type `child_bt`,
//!      which does its own `mmap` during runtime startup. That is
//!      the non-pre-exec syscall that forces `commit_delayed_fork`
//!      in the child; the snapshot it consults is the leaf's fd
//!      table at fork time, which contains the parent-side fd.
//!   3. The leaf reaps the child, closes the fd, and reports.
//!
//! Assertion is the same for accept- and reject-class fds: the test
//! passes if the child returns cleanly. We do **not** observe
//! migration vs. fall-through directly — the value of the matrix is
//! count-delta regression detection across both the reject list and
//! the CoW fall-through path (commit `5241b07c`).
//!
//! Test ID shape: `DF_PARENT_TRIGGER.<fd_class>.<parent_bt>.<child_bt>`
//! where `parent_bt` and `child_bt` use `BinaryType::short_label()`
//! (`dpg` / `dng` / `spg` / `spm` / `snm`).

#![allow(clippy::wildcard_enum_match_arm)]

use serde::{Deserialize, Serialize};

use super::agents::{AgentName, SpawnKind};
use super::registry::Registry;
use crate::handlers::{HandlerCtx, HandlerError, HandlerToken};
use crate::register_handler;

// ─── Parent fd classes ──────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
enum ParentFdKind {
    /// No extra fd opened — only stdio inherited.
    StdioOnly,
    /// `pipe2(O_CLOEXEC)` — accept-list (`FdKind::Pipe`).
    Pipe,
    /// `eventfd(0, EFD_CLOEXEC)` — accept-list (`FdKind::EventFd`).
    EventFd,
    /// `socketpair(AF_UNIX, SOCK_STREAM, 0)` — accept-list
    /// (`FdKind::UnixSocket`).
    UnixSocket,
    /// `signalfd(-1, &set, SFD_CLOEXEC)` — accept-list
    /// (`FdKind::Signalfd`).
    Signalfd,
    /// `socket(AF_INET, SOCK_STREAM, 0)` bound to 127.0.0.1:0 +
    /// `listen` — accept-list (`FdKind::InetListener`).
    InetListener,
    /// `open("/etc/hostname", O_RDONLY|O_CLOEXEC)` — accept-list
    /// (`FdKind::FilesystemFd`). `/etc/hostname` is a regular file
    /// in both the docker rootfs and the WSL2 chroot used for
    /// native baseline.
    FilesystemFd,
    /// `timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC)` — reject-list
    /// (`FdKind::TimerFd`).
    TimerFd,
    /// `epoll_create1(EPOLL_CLOEXEC)` — reject-list (`FdKind::Epoll`).
    Epoll,
    /// `inotify_init1(IN_CLOEXEC)` — reject-list (`FdKind::Inotify`).
    Inotify,
    /// `pidfd_open(getpid(), 0)` on self — reject-list
    /// (`FdKind::PidFd`).
    PidFd,
}

impl ParentFdKind {
    const ALL: &'static [ParentFdKind] = &[
        Self::StdioOnly,
        Self::Pipe,
        Self::EventFd,
        Self::UnixSocket,
        Self::Signalfd,
        Self::InetListener,
        Self::FilesystemFd,
        Self::TimerFd,
        Self::Epoll,
        Self::Inotify,
        Self::PidFd,
    ];

    const fn suffix(self) -> &'static str {
        match self {
            Self::StdioOnly => "stdio_only",
            Self::Pipe => "pipe",
            Self::EventFd => "eventfd",
            Self::UnixSocket => "unix_socket",
            Self::Signalfd => "signalfd",
            Self::InetListener => "inet_listener",
            Self::FilesystemFd => "filesystem_fd",
            Self::TimerFd => "timerfd",
            Self::Epoll => "epoll",
            Self::Inotify => "inotify",
            Self::PidFd => "pidfd",
        }
    }

    const fn wire(self) -> &'static str {
        // Same as `suffix()` — kept as a separate accessor so wire
        // and display can diverge without churning all sites.
        self.suffix()
    }

    fn from_wire(s: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|c| c.wire() == s)
    }
}

// ─── Parent binary types covered ────────────────────────────────────

/// Three representative binary types (out of five). Each appears as
/// both `parent_bt` and `child_bt`, giving 11 × 3 × 3 = 99 tests.
/// We exclude `StaticPieMusl` and `NonPieStaticMusl` here for build
/// budget; they're already covered by the broader `XDF.*` matrix
/// (which varies the child-side trigger).
const DF_PT_BINARIES: &[crate::BinaryType] = &[
    crate::BinaryType::PieGlibc,
    crate::BinaryType::NonPieGlibc,
    crate::BinaryType::StaticPieGlibc,
];

/// Mirror of `fork_matrix::fork_binary_label`. We keep a private copy
/// so this module doesn't depend on internals of `fork_matrix`.
const fn fork_binary_label(bt: crate::BinaryType) -> &'static str {
    match bt {
        crate::BinaryType::PieGlibc => "self",
        crate::BinaryType::NonPieGlibc => "nonpie",
        crate::BinaryType::StaticPieGlibc => "static-pie-glibc",
        crate::BinaryType::StaticPieMusl => "static-pie-musl",
        crate::BinaryType::NonPieStaticMusl => "non-pie-static-musl",
    }
}

// ─── Handler types ──────────────────────────────────────────────────

#[derive(Clone, Serialize, Deserialize)]
struct DfParentTriggerArgs {
    /// Wire form of [`ParentFdKind`].
    fd_class: String,
    /// Path to the child binary to fork+exec.
    child_cmd: String,
    /// argv for the child binary.
    child_args: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct DfParentTriggerOut {
    detail: String,
}

const DF_PARENT_TRIGGER: HandlerToken<DfParentTriggerArgs, DfParentTriggerOut> =
    HandlerToken::new("df_parent_trigger.run");

// ─── Fd opener ──────────────────────────────────────────────────────

/// Open one or more fds of the requested class. All returned fds are
/// closed by the caller on the success path; on the failure path the
/// caller still closes any partial set.
fn open_parent_fds(class: ParentFdKind) -> Result<Vec<libc::c_int>, String> {
    let errno = || std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
    match class {
        ParentFdKind::StdioOnly => Ok(Vec::new()),
        ParentFdKind::Pipe => {
            let mut fds = [0i32; 2];
            let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
            if rc != 0 {
                return Err(format!("pipe2: errno={}", errno()));
            }
            Ok(vec![fds[0], fds[1]])
        }
        ParentFdKind::EventFd => {
            let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC) };
            if fd < 0 {
                return Err(format!("eventfd: errno={}", errno()));
            }
            Ok(vec![fd])
        }
        ParentFdKind::UnixSocket => {
            let mut fds = [0i32; 2];
            let rc = unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                    0,
                    fds.as_mut_ptr(),
                )
            };
            if rc != 0 {
                return Err(format!("socketpair: errno={}", errno()));
            }
            Ok(vec![fds[0], fds[1]])
        }
        ParentFdKind::Signalfd => {
            let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
            unsafe {
                libc::sigemptyset(&raw mut set);
                libc::sigaddset(&raw mut set, libc::SIGUSR1);
            }
            let fd = unsafe { libc::signalfd(-1, &raw const set, libc::SFD_CLOEXEC) };
            if fd < 0 {
                return Err(format!("signalfd: errno={}", errno()));
            }
            Ok(vec![fd])
        }
        ParentFdKind::InetListener => {
            let fd =
                unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
            if fd < 0 {
                return Err(format!("socket(AF_INET): errno={}", errno()));
            }
            let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            addr.sin_family = {
                #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                let af = libc::AF_INET as u16;
                af
            };
            addr.sin_port = 0; // ephemeral
            // 127.0.0.1 in network byte order.
            addr.sin_addr.s_addr = u32::from_be_bytes([127, 0, 0, 1]).to_be();
            let rc = unsafe {
                libc::bind(
                    fd,
                    (&raw const addr).cast::<libc::sockaddr>(),
                    libc::socklen_t::try_from(std::mem::size_of::<libc::sockaddr_in>())
                        .unwrap_or(libc::socklen_t::MAX),
                )
            };
            if rc != 0 {
                let e = errno();
                unsafe { libc::close(fd) };
                return Err(format!("bind: errno={e}"));
            }
            let rc = unsafe { libc::listen(fd, 8) };
            if rc != 0 {
                let e = errno();
                unsafe { libc::close(fd) };
                return Err(format!("listen: errno={e}"));
            }
            Ok(vec![fd])
        }
        ParentFdKind::FilesystemFd => {
            let path = b"/etc/hostname\0";
            let fd = unsafe {
                libc::open(
                    path.as_ptr().cast::<libc::c_char>(),
                    libc::O_RDONLY | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(format!("open(/etc/hostname): errno={}", errno()));
            }
            Ok(vec![fd])
        }
        ParentFdKind::TimerFd => {
            let fd = unsafe { libc::timerfd_create(libc::CLOCK_MONOTONIC, libc::TFD_CLOEXEC) };
            if fd < 0 {
                return Err(format!("timerfd_create: errno={}", errno()));
            }
            Ok(vec![fd])
        }
        ParentFdKind::Epoll => {
            let fd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
            if fd < 0 {
                return Err(format!("epoll_create1: errno={}", errno()));
            }
            Ok(vec![fd])
        }
        ParentFdKind::Inotify => {
            let fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC) };
            if fd < 0 {
                return Err(format!("inotify_init1: errno={}", errno()));
            }
            Ok(vec![fd])
        }
        ParentFdKind::PidFd => {
            // pidfd_open is not in libc directly on all targets; use
            // the raw syscall number. SYS_pidfd_open = 434 on x86_64,
            // aarch64, and other Linux ABIs we care about.
            const SYS_PIDFD_OPEN: libc::c_long = 434;
            let pid = unsafe { libc::getpid() };
            let fd = unsafe { libc::syscall(SYS_PIDFD_OPEN, pid, 0) };
            if fd < 0 {
                return Err(format!("pidfd_open: errno={}", errno()));
            }
            let fd = libc::c_int::try_from(fd)
                .map_err(|_| format!("pidfd_open returned non-int fd value: {fd}"))?;
            // pidfd_open doesn't currently honor a CLOEXEC flag arg
            // (must use PIDFD_NONBLOCK only); set it explicitly so
            // we don't leak through the upcoming exec.
            let _ = unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
            Ok(vec![fd])
        }
    }
}

fn close_all(fds: &[libc::c_int]) {
    for &fd in fds {
        unsafe { libc::close(fd) };
    }
}

// ─── Handler body ───────────────────────────────────────────────────

async fn handle_df_parent_trigger(
    args: DfParentTriggerArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<DfParentTriggerOut, HandlerError> {
    let class = ParentFdKind::from_wire(&args.fd_class)
        .ok_or_else(|| HandlerError::from(format!("unknown fd_class: {}", args.fd_class)))?;

    let fds = open_parent_fds(class).map_err(HandlerError::from)?;

    // Sanity: each fd is observable via F_GETFD before we fork.
    for &fd in &fds {
        let rc = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if rc < 0 {
            let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
            close_all(&fds);
            return Err(HandlerError::from(format!(
                "pre-fork F_GETFD on fd={fd} failed errno={e}"
            )));
        }
    }

    // fork+exec the child trigger. The child binary will do its own
    // mmap during runtime startup; that mmap is the non-pre-exec
    // syscall that forces commit_delayed_fork in the child.
    let spawn_result = tokio::process::Command::new(&args.child_cmd)
        .args(&args.child_args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .await;

    close_all(&fds);

    let output = spawn_result.map_err(|e| {
        HandlerError::from(format!("child {} fork+exec failed: {e}", args.child_cmd))
    })?;

    if !output.status.success() {
        return Err(HandlerError::from(format!(
            "child {} exit={} stderr={}",
            args.child_cmd,
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    Ok(DfParentTriggerOut {
        detail: String::from_utf8_lossy(&output.stdout).to_string(),
    })
}

// ─── Registration ───────────────────────────────────────────────────

pub(crate) fn register_df_parent_trigger(reg: &mut Registry<'_>) {
    register_handler!(DF_PARENT_TRIGGER, handle_df_parent_trigger);

    for &fd_class in ParentFdKind::ALL {
        for &parent_bt in DF_PT_BINARIES {
            for &child_bt in DF_PT_BINARIES {
                let id = format!(
                    "DF_PARENT_TRIGGER.{}.{}.{}",
                    fd_class.suffix(),
                    parent_bt.short_label(),
                    child_bt.short_label()
                );
                let fd_wire = fd_class.wire().to_string();
                let leaf_label = format!(
                    "DFPT_{}_{}_{}",
                    fd_class.suffix(),
                    parent_bt.short_label(),
                    child_bt.short_label()
                );

                reg.test("fork", "df_parent_trigger", id)
                    .timeout(60)
                    .build(move |cx| {
                        let leaf = cx.declare_ephemeral(
                            AgentName::Dpg1,
                            leaf_label.clone(),
                            SpawnKind::Fork {
                                binary: fork_binary_label(parent_bt),
                                inherit_listen_ports: vec![],
                            },
                        );
                        let fd_wire = fd_wire.clone();
                        Box::new(move |run| {
                            let leaf = leaf.clone();
                            let fd_wire = fd_wire.clone();
                            Box::pin(async move {
                                let self_exe = run.self_exe().to_string();
                                let child_cmd = crate::binary_path(child_bt, &self_exe);
                                let result = run
                                    .run_leaf(
                                        &leaf,
                                        &DF_PARENT_TRIGGER,
                                        DfParentTriggerArgs {
                                            fd_class: fd_wire,
                                            child_cmd,
                                            child_args: vec!["echo-test".into()],
                                        },
                                    )
                                    .await;
                                let pass = matches!(
                                    &result,
                                    Ok(out) if out.detail.contains("ECHO_TEST_OK")
                                );
                                super::TestOutcome::new("A", pass, format!("{result:?}"))
                            })
                        })
                    });
            }
        }
    }
}
