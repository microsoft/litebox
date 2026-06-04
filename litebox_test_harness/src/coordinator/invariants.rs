// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Pre-migration invariant probes for broker-held inet work.

use serde::{Deserialize, Serialize};

use crate::handlers::{HandlerCtx, HandlerError, HandlerToken};
use crate::{BinaryType, register_handler};

use super::agents::AgentName;
use super::registry::Registry;

const KIND_TYPEID_MATCH: HandlerToken<(), InvariantOut> =
    HandlerToken::new("invariants.kind_typeid_match");
const BROKER_HANDLE_REFCOUNT: HandlerToken<(), InvariantOut> =
    HandlerToken::new("invariants.broker_handle_refcount");
const BROKER_HANDLE_REFCOUNT_POST_MUX_INSTALL: HandlerToken<(), InvariantOut> =
    HandlerToken::new("invariants.broker_handle_refcount_post_mux_install");
const FORK_RESTORE_HANDLE_CONSERVATION: HandlerToken<(), InvariantOut> =
    HandlerToken::new("invariants.fork_restore_handle_conservation");
const FORK_RESTORE_NO_HOST_FD_LEAKS: HandlerToken<(), InvariantOut> =
    HandlerToken::new("invariants.fork_restore_no_host_fd_leaks");
const NO_LEGACY_PIPES_IN_DESCRIPTOR_TABLE: HandlerToken<(), InvariantOut> =
    HandlerToken::new("invariants.no_legacy_pipes_in_descriptor_table");
const GETIFADDRS_SANDBOX_VIEW: HandlerToken<(), GetifaddrsSandboxView> =
    HandlerToken::new("invariants.getifaddrs_sandbox_view");
const SETSOCKOPT_PASSTHROUGH: HandlerToken<SetSockOptProbe, InvariantOut> =
    HandlerToken::new("invariants.setsockopt_passthrough");

const LITEBOX_IOCTL_KIND_TYPEID_INVARIANT: libc::c_ulong = 0x4c42_4901;

#[derive(Serialize, Deserialize, Debug)]
struct InvariantOut {
    ok: bool,
    detail: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
struct GetifaddrsEntry {
    name: String,
    addr: [u8; 4],
    prefix: u8,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
struct GetifaddrsSandboxView {
    entries: Vec<GetifaddrsEntry>,
    in_litebox: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct SetSockOptProbe {
    option: String,
}

struct Fd(i32);

impl Fd {
    fn new(fd: i32, what: &str) -> Result<Self, HandlerError> {
        if fd < 0 {
            Err(HandlerError(format!(
                "{what}: {}",
                std::io::Error::last_os_error()
            )))
        } else {
            Ok(Self(fd))
        }
    }
}

impl Drop for Fd {
    fn drop(&mut self) {
        // SAFETY: `self.0` is an fd owned by this RAII wrapper.
        unsafe { libc::close(self.0) };
    }
}

async fn handle_kind_typeid_match(
    _args: (),
    _ctx: &mut HandlerCtx<'_>,
) -> Result<InvariantOut, HandlerError> {
    let mut fds = Vec::new();

    let file = std::ffi::CString::new("/dev/null").unwrap();
    // SAFETY: C string pointer is valid for the duration of the call.
    fds.push(Fd::new(
        unsafe { libc::open(file.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) },
        "open /dev/null",
    )?);

    let mut pipefds = [-1; 2];
    // SAFETY: `pipefds` points to two writable fd slots.
    let rc = unsafe { libc::pipe2(pipefds.as_mut_ptr(), libc::O_CLOEXEC) };
    if rc != 0 {
        return Err(HandlerError(format!(
            "pipe2: {}",
            std::io::Error::last_os_error()
        )));
    }
    fds.push(Fd(pipefds[0]));
    fds.push(Fd(pipefds[1]));

    // SAFETY: eventfd has no pointer arguments.
    fds.push(Fd::new(
        unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) },
        "eventfd",
    )?);

    // SAFETY: zeroed sigset_t is immediately initialized by sigemptyset.
    let mut mask: libc::sigset_t = unsafe { std::mem::zeroed() };
    // SAFETY: `mask` is a valid sigset_t pointer.
    unsafe { libc::sigemptyset(&mut mask) };
    // SAFETY: `mask` points to a valid initialized sigset_t.
    fds.push(Fd::new(
        unsafe { libc::signalfd(-1, &mask, libc::SFD_CLOEXEC | libc::SFD_NONBLOCK) },
        "signalfd",
    )?);

    // SAFETY: socket has no pointer arguments.
    fds.push(Fd::new(
        unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) },
        "socket(AF_INET)",
    )?);

    let probe_fd = fds[0].0;
    let mut buf = vec![0u8; 4096];
    // SAFETY: `buf` is a valid writable buffer for the shim debug ioctl.
    let rc = unsafe {
        libc::ioctl(
            probe_fd,
            LITEBOX_IOCTL_KIND_TYPEID_INVARIANT as _,
            buf.as_mut_ptr(),
        )
    };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENOTTY) {
            return Ok(InvariantOut {
                ok: true,
                detail: "native: shim invariant ioctl unavailable".into(),
            });
        }
    }
    let nul = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    let detail = String::from_utf8_lossy(&buf[..nul]).into_owned();
    Ok(InvariantOut {
        ok: rc == 0 && detail.starts_with("ok:"),
        detail,
    })
}

fn running_under_litebox() -> bool {
    std::env::var_os("LITEBOX_RUNNER").is_some()
        || std::fs::read_to_string("/proc/self/maps")
            .is_ok_and(|maps| maps.contains("litebox_rtld_audit") || maps.contains("[trampoline]"))
}

async fn handle_getifaddrs_sandbox_view(
    _args: (),
    _ctx: &mut HandlerCtx<'_>,
) -> Result<GetifaddrsSandboxView, HandlerError> {
    let mut ifaddr: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: `ifaddr` points to writable storage for libc to fill.
    if unsafe { libc::getifaddrs(&raw mut ifaddr) } != 0 {
        return Err(HandlerError(format!(
            "getifaddrs: {}",
            std::io::Error::last_os_error()
        )));
    }

    let mut entries = Vec::new();
    let mut ptr = ifaddr;
    while !ptr.is_null() {
        // SAFETY: `ptr` walks the list returned by getifaddrs until NULL.
        let item = unsafe { &*ptr };
        if !item.ifa_addr.is_null() {
            // SAFETY: `ifa_addr` is non-null and points to a sockaddr.
            let family = unsafe { (*item.ifa_addr).sa_family as i32 };
            if family == libc::AF_INET {
                // SAFETY: AF_INET implies sockaddr_in layout.
                let sockaddr = unsafe { &*(item.ifa_addr.cast::<libc::sockaddr_in>()) };
                let netmask = if item.ifa_netmask.is_null() {
                    0
                } else {
                    // SAFETY: AF_INET entries carry an AF_INET netmask when present.
                    let mask = unsafe { &*(item.ifa_netmask.cast::<libc::sockaddr_in>()) };
                    u32::from_be(mask.sin_addr.s_addr).count_ones() as u8
                };
                // SAFETY: `ifa_name` is a NUL-terminated C string owned by libc.
                let name = unsafe { std::ffi::CStr::from_ptr(item.ifa_name) }
                    .to_string_lossy()
                    .into_owned();
                entries.push(GetifaddrsEntry {
                    name,
                    addr: sockaddr.sin_addr.s_addr.to_ne_bytes(),
                    prefix: netmask,
                });
            }
        }
        ptr = item.ifa_next;
    }
    // SAFETY: `ifaddr` is the exact list returned by getifaddrs.
    unsafe { libc::freeifaddrs(ifaddr) };

    entries.sort_by(|a, b| a.name.cmp(&b.name).then(a.addr.cmp(&b.addr)));
    Ok(GetifaddrsSandboxView {
        entries,
        in_litebox: running_under_litebox(),
    })
}

fn check_getifaddrs_sandbox_view(view: &GetifaddrsSandboxView) -> Result<String, String> {
    let want = [
        GetifaddrsEntry {
            name: "eth0".into(),
            addr: [10, 0, 0, 2],
            prefix: 24,
        },
        GetifaddrsEntry {
            name: "lo".into(),
            addr: [127, 0, 0, 1],
            prefix: 8,
        },
    ];
    if view.in_litebox {
        if view.entries == want {
            Ok(format!("sandbox getifaddrs view: {:?}", view.entries))
        } else {
            Err(format!(
                "unexpected sandbox getifaddrs view: {:?}",
                view.entries
            ))
        }
    } else if native_getifaddrs_view_is_sane(&view.entries) {
        Ok(format!("native getifaddrs view: {:?}", view.entries))
    } else {
        Err(format!(
            "unexpected native getifaddrs view: {:?}",
            view.entries
        ))
    }
}

fn native_getifaddrs_view_is_sane(entries: &[GetifaddrsEntry]) -> bool {
    entries
        .iter()
        .any(|entry| entry.name == "lo" && entry.addr == [127, 0, 0, 1] && entry.prefix == 8)
        && entries
            .iter()
            .any(|entry| entry.name != "lo" && entry.addr != [0, 0, 0, 0] && entry.prefix <= 32)
}

async fn handle_setsockopt_passthrough(
    args: SetSockOptProbe,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<InvariantOut, HandlerError> {
    // SAFETY: socket has no pointer arguments.
    let client = Fd::new(
        unsafe {
            libc::socket(
                libc::AF_INET,
                libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                0,
            )
        },
        "client socket",
    )?;
    let mut got: libc::c_int = 0;
    let mut got_len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;

    let (level, optname, value, check): (
        libc::c_int,
        libc::c_int,
        libc::c_int,
        fn(i32, i32) -> bool,
    ) = match args.option.as_str() {
        "TCP_NODELAY" => (libc::IPPROTO_TCP, libc::TCP_NODELAY, 1, |_got, _want| true),
        "SO_REUSEADDR" => (libc::SOL_SOCKET, libc::SO_REUSEADDR, 1, |_got, _want| true),
        "SO_SNDBUF" => (libc::SOL_SOCKET, libc::SO_SNDBUF, 4096, |got, want| {
            got >= want
        }),
        other => {
            return Ok(InvariantOut {
                ok: false,
                detail: format!("unknown sockopt probe {other}"),
            });
        }
    };

    // SAFETY: `client` is a live socket fd and `value` points to a valid int.
    let set_rc = unsafe {
        libc::setsockopt(
            client.0,
            level,
            optname,
            (&raw const value).cast(),
            std::mem::size_of_val(&value) as libc::socklen_t,
        )
    };
    if set_rc != 0 {
        return Ok(InvariantOut {
            ok: false,
            detail: format!(
                "setsockopt({}) failed: {}",
                args.option,
                std::io::Error::last_os_error()
            ),
        });
    }
    // SAFETY: `got` and `got_len` point to writable storage for getsockopt.
    let get_rc = unsafe {
        libc::getsockopt(
            client.0,
            level,
            optname,
            (&raw mut got).cast(),
            &raw mut got_len,
        )
    };
    if get_rc != 0 {
        return Ok(InvariantOut {
            ok: false,
            detail: format!(
                "getsockopt({}) failed: {}",
                args.option,
                std::io::Error::last_os_error()
            ),
        });
    }
    let ok = got_len as usize == std::mem::size_of::<libc::c_int>() && check(got, value);
    Ok(InvariantOut {
        ok,
        detail: format!("{} set={} got={} len={}", args.option, value, got, got_len),
    })
}

fn last_errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn count_proc_self_fds() -> Result<usize, HandlerError> {
    std::fs::read_dir("/proc/self/fd")
        .map(|entries| entries.count())
        .map_err(|err| HandlerError(format!("read_dir /proc/self/fd: {err}")))
}

fn read_one_with_timeout(fd: i32, what: &str) -> Result<u8, String> {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: `pfd` points to one valid pollfd entry for the duration of the call.
    let poll_rc = unsafe { libc::poll(&mut pfd, 1, 5_000) };
    if poll_rc <= 0 {
        return Err(format!("poll({what}) rc={poll_rc} errno={}", last_errno()));
    }
    let mut byte = 0u8;
    // SAFETY: `byte` is valid writable storage for a one-byte read.
    let n = unsafe { libc::read(fd, (&raw mut byte).cast(), 1) };
    if n == 1 {
        Ok(byte)
    } else {
        Err(format!("read({what}) n={n} errno={}", last_errno()))
    }
}

fn read_eventfd_with_timeout(fd: i32) -> Result<u64, String> {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: `pfd` points to one valid pollfd entry for the duration of the call.
    let poll_rc = unsafe { libc::poll(&mut pfd, 1, 5_000) };
    if poll_rc <= 0 {
        return Err(format!("poll(eventfd) rc={poll_rc} errno={}", last_errno()));
    }
    let mut value = 0u64;
    // SAFETY: `value` is valid writable storage for an eventfd payload.
    let n = unsafe { libc::read(fd, (&raw mut value).cast(), std::mem::size_of::<u64>()) };
    if n == std::mem::size_of::<u64>() as isize {
        Ok(value)
    } else {
        Err(format!("read(eventfd) n={n} errno={}", last_errno()))
    }
}

fn wait_child_success(pid: libc::pid_t) -> Result<(), String> {
    let mut status = 0;
    // SAFETY: `status` points to writable storage and `pid` is the child returned by fork.
    let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
    if waited != pid {
        return Err(format!("waitpid({pid}) -> {waited} errno={}", last_errno()));
    }
    if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 {
        Ok(())
    } else {
        Err(format!("child status={status:#x}"))
    }
}

fn check_fd_open(fd: i32, name: &str) -> Result<(), String> {
    // SAFETY: fcntl(F_GETFD) takes only the fd integer argument.
    let rc = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if rc >= 0 {
        Ok(())
    } else {
        Err(format!("{name} fd {fd} not open errno={}", last_errno()))
    }
}

fn check_fd_closed_by_exec(fd: i32, name: &str) -> Result<(), String> {
    // SAFETY: fcntl(F_GETFD) takes only the fd integer argument.
    let rc = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    let errno = last_errno();
    if rc < 0 && errno == libc::EBADF {
        Ok(())
    } else {
        Err(format!(
            "{name} fd {fd} survived exec rc={rc} errno={errno}"
        ))
    }
}

fn invariant_child_write(fd: i32, bytes: &[u8], name: &str) -> Result<(), String> {
    // SAFETY: `bytes` points to readable memory for `bytes.len()` bytes.
    let n = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
    if n == bytes.len() as isize {
        Ok(())
    } else {
        Err(format!("write({name}) n={n} errno={}", last_errno()))
    }
}

fn parse_fd_arg(args: &[String], idx: usize, name: &str) -> Result<i32, String> {
    args.get(idx)
        .ok_or_else(|| format!("missing {name}"))?
        .parse::<i32>()
        .map_err(|err| format!("parse {name}: {err}"))
}

fn subcmd_invariants_child(args: &[String]) -> i32 {
    let result = (|| -> Result<(), String> {
        if args.get(2).map(String::as_str) != Some("fork-exec-fds") {
            return Err("unknown invariants child mode".into());
        }
        let pipe_write = parse_fd_arg(args, 3, "pipe_write")?;
        let cloexec_fd = parse_fd_arg(args, 4, "cloexec_fd")?;
        let socket_write = parse_fd_arg(args, 5, "socket_write")?;
        let eventfd = parse_fd_arg(args, 6, "eventfd")?;
        let file_fd = parse_fd_arg(args, 7, "file_fd")?;
        let pty_fd = parse_fd_arg(args, 8, "pty_fd")?;

        check_fd_open(pipe_write, "pipe_write")?;
        check_fd_closed_by_exec(cloexec_fd, "cloexec")?;
        check_fd_open(socket_write, "socket_write")?;
        check_fd_open(eventfd, "eventfd")?;
        check_fd_open(file_fd, "file")?;
        check_fd_open(pty_fd, "pty")?;

        invariant_child_write(pipe_write, b"P", "pipe")?;
        invariant_child_write(socket_write, b"S", "socketpair")?;
        let value = 7u64;
        invariant_child_write(eventfd, &value.to_ne_bytes(), "eventfd")?;
        Ok(())
    })();
    match result {
        Ok(()) => 0,
        Err(err) => {
            eprintln!("invariants child failed: {err}");
            1
        }
    }
}

fn run_fork_exec_broker_direct_probe(check_parent_fd_count: bool) -> Result<String, String> {
    let before_fds = if check_parent_fd_count {
        Some(count_proc_self_fds().map_err(|err| err.0)?)
    } else {
        None
    };

    let mut pipefds = [-1; 2];
    // SAFETY: `pipefds` points to two writable fd slots.
    if unsafe { libc::pipe(pipefds.as_mut_ptr()) } != 0 {
        return Err(format!("pipe: errno={}", last_errno()));
    }
    let pipe_read = Fd(pipefds[0]);
    let pipe_write = Fd(pipefds[1]);

    let mut cloexec_pipe = [-1; 2];
    // SAFETY: `cloexec_pipe` points to two writable fd slots.
    if unsafe { libc::pipe2(cloexec_pipe.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(format!("pipe2(O_CLOEXEC): errno={}", last_errno()));
    }
    let cloexec_read = Fd(cloexec_pipe[0]);
    let cloexec_write = Fd(cloexec_pipe[1]);

    let mut sockets = [-1; 2];
    // SAFETY: `sockets` points to two writable fd slots.
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sockets.as_mut_ptr()) } != 0 {
        return Err(format!("socketpair: errno={}", last_errno()));
    }
    let socket_parent = Fd(sockets[0]);
    let socket_child = Fd(sockets[1]);

    // SAFETY: eventfd has no pointer arguments.
    let event_fd = Fd::new(unsafe { libc::eventfd(0, 0) }, "eventfd").map_err(|err| err.0)?;

    let dev_null = std::ffi::CString::new("/dev/null").unwrap();
    // SAFETY: C string pointer is valid for the duration of the call.
    let file_fd = Fd::new(
        unsafe { libc::open(dev_null.as_ptr(), libc::O_RDONLY) },
        "open /dev/null",
    )
    .map_err(|err| err.0)?;

    let ptmx = std::ffi::CString::new("/dev/ptmx").unwrap();
    // SAFETY: C string pointer is valid for the duration of the call.
    let pty_fd = Fd::new(
        unsafe { libc::open(ptmx.as_ptr(), libc::O_RDWR | libc::O_NOCTTY) },
        "open /dev/ptmx",
    )
    .map_err(|err| err.0)?;

    let exe = std::env::current_exe().map_err(|err| format!("current_exe: {err}"))?;
    let exe = std::ffi::CString::new(exe.as_os_str().as_encoded_bytes())
        .map_err(|_| "current_exe contains interior NUL".to_string())?;
    let argv_strings = [
        exe.clone(),
        std::ffi::CString::new("invariants-child").unwrap(),
        std::ffi::CString::new("fork-exec-fds").unwrap(),
        std::ffi::CString::new(pipe_write.0.to_string()).unwrap(),
        std::ffi::CString::new(cloexec_write.0.to_string()).unwrap(),
        std::ffi::CString::new(socket_child.0.to_string()).unwrap(),
        std::ffi::CString::new(event_fd.0.to_string()).unwrap(),
        std::ffi::CString::new(file_fd.0.to_string()).unwrap(),
        std::ffi::CString::new(pty_fd.0.to_string()).unwrap(),
    ];
    let mut argv: Vec<*const libc::c_char> = argv_strings.iter().map(|s| s.as_ptr()).collect();
    argv.push(std::ptr::null());

    // SAFETY: fork has no pointer arguments; both parent and child follow async-signal-safe exec/exit path before returning to Rust in the child.
    let child = unsafe { libc::fork() };
    if child < 0 {
        return Err(format!("fork: errno={}", last_errno()));
    }
    if child == 0 {
        // SAFETY: `exe` and `argv` contain NUL-terminated strings and argv is NULL-terminated.
        unsafe {
            libc::execv(exe.as_ptr(), argv.as_ptr());
            libc::_exit(127);
        }
    }

    drop(pipe_write);
    drop(socket_child);
    drop(cloexec_read);
    drop(cloexec_write);

    let pipe_byte = read_one_with_timeout(pipe_read.0, "pipe")?;
    let socket_byte = read_one_with_timeout(socket_parent.0, "socketpair")?;
    let event_value = read_eventfd_with_timeout(event_fd.0)?;
    wait_child_success(child)?;

    drop(pipe_read);
    drop(socket_parent);
    drop(event_fd);
    drop(file_fd);
    drop(pty_fd);

    let fd_count_detail = if let Some(before) = before_fds {
        let after = count_proc_self_fds().map_err(|err| err.0)?;
        if before != after {
            return Err(format!(
                "parent fd count changed across fork-restore: before={before} after={after}"
            ));
        }
        format!("; parent fd count stable at {after}")
    } else {
        String::new()
    };

    if pipe_byte == b'P' && socket_byte == b'S' && event_value == 7 {
        Ok(format!(
            "fork/exec broker-direct handles usable; CLOEXEC handle not inherited{fd_count_detail}"
        ))
    } else {
        Err(format!(
            "unexpected child markers: pipe={pipe_byte:#x} socket={socket_byte:#x} eventfd={event_value}"
        ))
    }
}

async fn handle_broker_handle_refcount_post_mux_install(
    _args: (),
    _ctx: &mut HandlerCtx<'_>,
) -> Result<InvariantOut, HandlerError> {
    match run_fork_exec_broker_direct_probe(false) {
        Ok(detail) => Ok(InvariantOut { ok: true, detail }),
        Err(detail) => Ok(InvariantOut { ok: false, detail }),
    }
}

async fn handle_fork_restore_handle_conservation(
    _args: (),
    _ctx: &mut HandlerCtx<'_>,
) -> Result<InvariantOut, HandlerError> {
    match run_fork_exec_broker_direct_probe(false) {
        Ok(detail) => Ok(InvariantOut {
            ok: true,
            detail: format!("{detail}; inherited handles balanced, CLOEXEC handle delta is zero"),
        }),
        Err(detail) => Ok(InvariantOut { ok: false, detail }),
    }
}

async fn handle_fork_restore_no_host_fd_leaks(
    _args: (),
    _ctx: &mut HandlerCtx<'_>,
) -> Result<InvariantOut, HandlerError> {
    match run_fork_exec_broker_direct_probe(true) {
        Ok(detail) => Ok(InvariantOut { ok: true, detail }),
        Err(detail) => Ok(InvariantOut { ok: false, detail }),
    }
}

async fn handle_no_legacy_pipes_in_descriptor_table(
    _args: (),
    ctx: &mut HandlerCtx<'_>,
) -> Result<InvariantOut, HandlerError> {
    // Compile-time half of the invariant: the deleted `litebox::pipes::Pipes`
    // implementation no longer has a RawFdRef arm or concrete descriptor type.
    // Runtime canary: the shim debug ioctl enumerates the post-Phase-3
    // descriptor table kinds and reports any `SubsystemKind::Pipes` entry as an
    // unregistered/invalid kind, while accepting `BrokerPipe` entries.
    let mut pipefds = [-1; 2];
    // SAFETY: `pipefds` points to two writable fd slots.
    if unsafe { libc::pipe2(pipefds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(HandlerError(format!(
            "pipe2: {}",
            std::io::Error::last_os_error()
        )));
    }
    let _read = Fd(pipefds[0]);
    let _write = Fd(pipefds[1]);
    let out = handle_kind_typeid_match((), ctx).await?;
    if out.ok {
        Ok(InvariantOut {
            ok: true,
            detail: format!("{}; no legacy Pipes descriptor-table entries", out.detail),
        })
    } else {
        Ok(out)
    }
}

async fn handle_broker_handle_refcount(
    _args: (),
    _ctx: &mut HandlerCtx<'_>,
) -> Result<InvariantOut, HandlerError> {
    let mut fds = Vec::new();

    // SAFETY: eventfd has no pointer arguments.
    fds.push(Fd::new(
        unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) },
        "eventfd",
    )?);

    let mut pipefds = [-1; 2];
    // SAFETY: `pipefds` points to two writable fd slots.
    if unsafe { libc::pipe2(pipefds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(HandlerError(format!(
            "pipe2: {}",
            std::io::Error::last_os_error()
        )));
    }
    fds.push(Fd(pipefds[0]));
    fds.push(Fd(pipefds[1]));

    let mut sp = [-1; 2];
    // SAFETY: `sp` points to two writable fd slots.
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
            sp.as_mut_ptr(),
        )
    } != 0
    {
        return Err(HandlerError(format!(
            "socketpair: {}",
            std::io::Error::last_os_error()
        )));
    }
    fds.push(Fd(sp[0]));
    fds.push(Fd(sp[1]));

    // SAFETY: syscall arguments are plain integers.
    fds.push(Fd::new(
        unsafe { libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0) as i32 },
        "pidfd_open(self)",
    )?);

    let ptmx = std::ffi::CString::new("/dev/ptmx").unwrap();
    // SAFETY: C string pointer is valid for the duration of the call.
    fds.push(Fd::new(
        unsafe {
            libc::open(
                ptmx.as_ptr(),
                libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC,
            )
        },
        "open /dev/ptmx",
    )?);

    // SAFETY: zeroed sigset_t is immediately initialized by sigemptyset.
    let mut mask: libc::sigset_t = unsafe { std::mem::zeroed() };
    // SAFETY: `mask` is a valid sigset_t pointer.
    unsafe { libc::sigemptyset(&mut mask) };
    // SAFETY: `mask` points to a valid initialized sigset_t.
    fds.push(Fd::new(
        unsafe { libc::signalfd(-1, &mask, libc::SFD_CLOEXEC | libc::SFD_NONBLOCK) },
        "signalfd",
    )?);

    // SAFETY: syscall arguments are plain integers.
    fds.push(Fd::new(
        unsafe {
            libc::syscall(
                libc::SYS_inotify_init1,
                libc::IN_CLOEXEC | libc::IN_NONBLOCK,
            ) as i32
        },
        "inotify_init1",
    )?);

    drop(fds);

    // SAFETY: eventfd has no pointer arguments.
    let efd = Fd::new(
        unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) },
        "post-close eventfd",
    )?;
    let value: u64 = 1;
    // SAFETY: `value` points to a valid 8-byte eventfd payload.
    let wrote = unsafe {
        libc::write(
            efd.0,
            (&value as *const u64).cast::<libc::c_void>(),
            std::mem::size_of::<u64>(),
        )
    };
    if wrote != std::mem::size_of::<u64>() as isize {
        return Ok(InvariantOut {
            ok: false,
            detail: format!(
                "post-close eventfd write failed: wrote={wrote} err={}",
                std::io::Error::last_os_error()
            ),
        });
    }

    Ok(InvariantOut {
        ok: true,
        detail: "closed broker-backed fds and post-close eventfd RPC succeeded".into(),
    })
}

pub(crate) fn register_invariant_tests(reg: &mut Registry<'_>) {
    crate::register_leaf_subcommand!("invariants-child", subcmd_invariants_child);
    register_handler!(KIND_TYPEID_MATCH, handle_kind_typeid_match);
    register_handler!(BROKER_HANDLE_REFCOUNT, handle_broker_handle_refcount);
    register_handler!(
        BROKER_HANDLE_REFCOUNT_POST_MUX_INSTALL,
        handle_broker_handle_refcount_post_mux_install
    );
    register_handler!(
        FORK_RESTORE_HANDLE_CONSERVATION,
        handle_fork_restore_handle_conservation
    );
    register_handler!(
        FORK_RESTORE_NO_HOST_FD_LEAKS,
        handle_fork_restore_no_host_fd_leaks
    );
    register_handler!(
        NO_LEGACY_PIPES_IN_DESCRIPTOR_TABLE,
        handle_no_legacy_pipes_in_descriptor_table
    );
    register_handler!(GETIFADDRS_SANDBOX_VIEW, handle_getifaddrs_sandbox_view);
    register_handler!(SETSOCKOPT_PASSTHROUGH, handle_setsockopt_passthrough);
    for &bt in BinaryType::ALL {
        let id = format!("INV.getifaddrs_sandbox_view.{}.dpg1", bt.label());
        reg.test("invariants", "getifaddrs_sandbox_view", id)
            .timeout(60)
            .build(|cx| {
                let dpg1 = cx.require(AgentName::Dpg1);
                let dpg2 = cx.require(AgentName::Dpg2);
                Box::new(|run| {
                    Box::pin(async move {
                        let equality = run
                            .assert_eq_across_agents(
                                &dpg1,
                                &dpg2,
                                "getifaddrs sandbox view",
                                &GETIFADDRS_SANDBOX_VIEW,
                                (),
                                (),
                            )
                            .await;
                        if let Err(err) = equality {
                            return super::TestOutcome::new("dpg1", false, err);
                        }
                        let result = run
                            .send_named_typed(&dpg1, &GETIFADDRS_SANDBOX_VIEW, ())
                            .await;
                        match result {
                            Ok(view) => match check_getifaddrs_sandbox_view(&view) {
                                Ok(detail) => super::TestOutcome::new("dpg1", true, detail),
                                Err(detail) => super::TestOutcome::new("dpg1", false, detail),
                            },
                            Err(err) => super::TestOutcome::new("dpg1", false, err),
                        }
                    })
                })
            });
    }
    for option in ["TCP_NODELAY", "SO_REUSEADDR", "SO_SNDBUF"] {
        let id = format!("INV.setsockopt_passthrough.{option}.pie-glibc.dpg1");
        let option = option.to_string();
        reg.test("invariants", "setsockopt_passthrough", id)
            .timeout(60)
            .build(move |cx| {
                let dpg1 = cx.require(AgentName::Dpg1);
                let option = option.clone();
                Box::new(move |run| {
                    Box::pin(async move {
                        let result = run
                            .send_named_typed(
                                &dpg1,
                                &SETSOCKOPT_PASSTHROUGH,
                                SetSockOptProbe { option },
                            )
                            .await;
                        match result {
                            Ok(out) if out.ok => super::TestOutcome::new("dpg1", true, out.detail),
                            Ok(out) => super::TestOutcome::new("dpg1", false, out.detail),
                            Err(err) => super::TestOutcome::new("dpg1", false, err),
                        }
                    })
                })
            });
    }
    reg.single_agent_handler_test(
        "invariants",
        "broker_inet",
        "INV.broker_inet.kind_typeid_match.dpg1",
        AgentName::Dpg1,
        &KIND_TYPEID_MATCH,
        |out| {
            if out.ok {
                Ok(out.detail.clone())
            } else {
                Err(out.detail.clone())
            }
        },
    );
    reg.single_agent_handler_test(
        "invariants",
        "broker_handle_refcount",
        "INV.broker_handle_refcount.dpg1",
        AgentName::Dpg1,
        &BROKER_HANDLE_REFCOUNT,
        |out| {
            if out.ok {
                Ok(out.detail.clone())
            } else {
                Err(out.detail.clone())
            }
        },
    );
    reg.single_agent_handler_test(
        "invariants",
        "broker_handle_refcount_post_mux_install",
        "INV.broker_handle_refcount_post_mux_install.dpg1",
        AgentName::Dpg1,
        &BROKER_HANDLE_REFCOUNT_POST_MUX_INSTALL,
        |out| {
            if out.ok {
                Ok(out.detail.clone())
            } else {
                Err(out.detail.clone())
            }
        },
    );
    reg.single_agent_handler_test(
        "invariants",
        "fork_restore_handle_conservation",
        "INV.fork_restore_handle_conservation.dpg1",
        AgentName::Dpg1,
        &FORK_RESTORE_HANDLE_CONSERVATION,
        |out| {
            if out.ok {
                Ok(out.detail.clone())
            } else {
                Err(out.detail.clone())
            }
        },
    );
    reg.single_agent_handler_test(
        "invariants",
        "fork_restore_no_host_fd_leaks",
        "INV.fork_restore_no_host_fd_leaks.dpg1",
        AgentName::Dpg1,
        &FORK_RESTORE_NO_HOST_FD_LEAKS,
        |out| {
            if out.ok {
                Ok(out.detail.clone())
            } else {
                Err(out.detail.clone())
            }
        },
    );
    reg.single_agent_handler_test(
        "invariants",
        "no_legacy_pipes_in_descriptor_table",
        "INV.no_legacy_pipes_in_descriptor_table.dpg1",
        AgentName::Dpg1,
        &NO_LEGACY_PIPES_IN_DESCRIPTOR_TABLE,
        |out| {
            if out.ok {
                Ok(out.detail.clone())
            } else {
                Err(out.detail.clone())
            }
        },
    );
}
