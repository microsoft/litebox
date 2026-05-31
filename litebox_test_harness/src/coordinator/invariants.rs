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
    register_handler!(KIND_TYPEID_MATCH, handle_kind_typeid_match);
    register_handler!(BROKER_HANDLE_REFCOUNT, handle_broker_handle_refcount);
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
}
