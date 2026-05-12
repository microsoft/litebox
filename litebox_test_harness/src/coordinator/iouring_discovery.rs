// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! `io_uring` discovery tests for VS Code startup blockers.
//!
//! Migrated to the typed-handler protocol. Each scenario is one
//! `Command::Run` to a registered handler that performs the
//! `io_uring` / epoll probe inline on the target agent.

use serde::{Deserialize, Serialize};

use crate::handlers::{HandlerCtx, HandlerError, HandlerToken};
use crate::register_handler;

use super::agents::AgentName;
use super::registry::Registry;

const ENOSYS: i32 = libc::ENOSYS;
const EOPNOTSUPP: i32 = libc::EOPNOTSUPP;

pub(crate) const IOR_AGENTS: &[AgentName] =
    &[AgentName::Dpg1, AgentName::Dpg1Dpg1, AgentName::Dpg2];

// ─── Kernel ABI shims ───────────────────────────────────────────────

#[repr(C)]
#[derive(Default)]
struct IoSqringOffsets {
    head: u32,
    tail: u32,
    ring_mask: u32,
    ring_entries: u32,
    flags: u32,
    dropped: u32,
    array: u32,
    resv1: u32,
    user_addr: u64,
}

#[repr(C)]
#[derive(Default)]
struct IoCqringOffsets {
    head: u32,
    tail: u32,
    ring_mask: u32,
    ring_entries: u32,
    overflow: u32,
    cqes: u32,
    flags: u32,
    resv1: u32,
    user_addr: u64,
}

#[repr(C)]
#[derive(Default)]
struct IoUringParams {
    sq_entries: u32,
    cq_entries: u32,
    flags: u32,
    sq_thread_cpu: u32,
    sq_thread_idle: u32,
    features: u32,
    wq_fd: u32,
    resv: [u32; 3],
    sq_off: IoSqringOffsets,
    cq_off: IoCqringOffsets,
}

// ─── Args / outputs ─────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
struct IoUringOutcome {
    ring_fd: i32,
    errno: Option<i32>,
}

#[derive(Serialize, Deserialize, Debug)]
struct EpollAfterOut {
    io_uring: IoUringOutcome,
    epoll: EpollOutcome,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
struct EpollOutcome {
    epoll_fd: i32,
    errno: Option<i32>,
}

#[derive(Serialize, Deserialize, Debug)]
struct RepeatedSetupOut {
    first: IoUringOutcome,
    second: IoUringOutcome,
    third: IoUringOutcome,
}

// ─── Typed handler tokens ───────────────────────────────────────────

const SETUP_RETURNS_DOCUMENTED_OUTCOME: HandlerToken<(), IoUringOutcome> =
    HandlerToken::new("iouring.setup_returns_documented_outcome");
const EPOLL_WORKS_AFTER_IOURING_REFUSAL: HandlerToken<(), EpollAfterOut> =
    HandlerToken::new("iouring.epoll_works_after_iouring_refusal");
const REPEATED_SETUP_CONSISTENT: HandlerToken<(), RepeatedSetupOut> =
    HandlerToken::new("iouring.repeated_setup_consistent");

// ─── Handlers ───────────────────────────────────────────────────────

async fn handle_setup_returns_documented_outcome(
    _args: (),
    _ctx: &mut HandlerCtx<'_>,
) -> Result<IoUringOutcome, HandlerError> {
    let outcome = io_uring_setup_probe(8);
    if !is_documented_outcome(outcome) {
        return Err(HandlerError(format!(
            "undocumented io_uring outcome: {outcome:?}"
        )));
    }
    Ok(outcome)
}

async fn handle_epoll_works_after_iouring_refusal(
    _args: (),
    _ctx: &mut HandlerCtx<'_>,
) -> Result<EpollAfterOut, HandlerError> {
    let io_uring = io_uring_setup_probe(8);
    if !is_documented_outcome(io_uring) {
        return Err(HandlerError(format!(
            "undocumented io_uring outcome: {io_uring:?}"
        )));
    }
    let epoll = epoll_open_probe();
    if epoll
        != (EpollOutcome {
            epoll_fd: 1,
            errno: None,
        })
    {
        return Err(HandlerError(format!(
            "epoll fallback failed after io_uring={io_uring:?}: epoll={epoll:?}"
        )));
    }
    Ok(EpollAfterOut { io_uring, epoll })
}

async fn handle_repeated_setup_consistent(
    _args: (),
    _ctx: &mut HandlerCtx<'_>,
) -> Result<RepeatedSetupOut, HandlerError> {
    let first = io_uring_setup_probe(8);
    let second = io_uring_setup_probe(8);
    let third = io_uring_setup_probe(8);
    if !is_documented_outcome(first) || first != second || second != third {
        return Err(HandlerError(format!(
            "inconsistent io_uring outcomes: first={first:?}; second={second:?}; third={third:?}"
        )));
    }
    Ok(RepeatedSetupOut {
        first,
        second,
        third,
    })
}

// ─── Registration ───────────────────────────────────────────────────

pub(crate) fn register_iouring_discovery_tests(reg: &mut Registry<'_>) {
    register_handler!(
        SETUP_RETURNS_DOCUMENTED_OUTCOME,
        handle_setup_returns_documented_outcome
    );
    register_handler!(
        EPOLL_WORKS_AFTER_IOURING_REFUSAL,
        handle_epoll_works_after_iouring_refusal
    );
    register_handler!(REPEATED_SETUP_CONSISTENT, handle_repeated_setup_consistent);

    for &agent in IOR_AGENTS {
        reg.single_agent_handler_test(
            "vscode",
            "iouring",
            format!("IOR.setup_returns_documented_outcome.{agent}"),
            agent,
            &SETUP_RETURNS_DOCUMENTED_OUTCOME,
            |out| Ok(format!("{out:?}")),
        );
        reg.single_agent_handler_test(
            "vscode",
            "iouring",
            format!("IOR.epoll_works_after_iouring_refusal.{agent}"),
            agent,
            &EPOLL_WORKS_AFTER_IOURING_REFUSAL,
            |out| {
                Ok(format!(
                    "io_uring={:?}; epoll={:?}",
                    out.io_uring, out.epoll
                ))
            },
        );
        reg.single_agent_handler_test(
            "vscode",
            "iouring",
            format!("IOR.repeated_setup_consistent.{agent}"),
            agent,
            &REPEATED_SETUP_CONSISTENT,
            |out| {
                Ok(format!(
                    "first={:?}; second={:?}; third={:?}",
                    out.first, out.second, out.third
                ))
            },
        );
    }
}

// ─── Probe helpers ──────────────────────────────────────────────────

fn io_uring_setup_probe(entries: u32) -> IoUringOutcome {
    let mut params = IoUringParams::default();
    // SAFETY: `params` points to a valid writable C-compatible
    // io_uring_params buffer for the duration of the syscall, and the
    // kernel does not retain the pointer after returning.
    let ret = unsafe { libc::syscall(libc::SYS_io_uring_setup, entries, &raw mut params) };
    if ret >= 0 {
        // The discovery probe only needs to know that the kernel returned a
        // descriptor. Close it immediately and report a stable positive
        // sentinel instead of leaking a ring fd.
        // SAFETY: `ret` is a fresh fd returned by io_uring_setup; close
        // consumes only that fd and no Rust object owns it.
        let Ok(fd) = i32::try_from(ret) else {
            return IoUringOutcome {
                ring_fd: -1,
                errno: Some(libc::EOVERFLOW),
            };
        };
        unsafe {
            libc::close(fd);
        }
        IoUringOutcome {
            ring_fd: 1,
            errno: None,
        }
    } else {
        IoUringOutcome {
            ring_fd: -1,
            errno: Some(errno()),
        }
    }
}

fn epoll_open_probe() -> EpollOutcome {
    // SAFETY: epoll_create1 takes an integer flag word and returns a new fd or
    // -1; no pointers or aliases are involved.
    let ret = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
    if ret >= 0 {
        // SAFETY: `ret` is a fresh fd returned by epoll_create1.
        unsafe {
            libc::close(ret);
        }
        EpollOutcome {
            epoll_fd: 1,
            errno: None,
        }
    } else {
        EpollOutcome {
            epoll_fd: -1,
            errno: Some(errno()),
        }
    }
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn is_documented_outcome(outcome: IoUringOutcome) -> bool {
    matches!(
        outcome,
        IoUringOutcome {
            ring_fd: 1,
            errno: None,
        } | IoUringOutcome {
            ring_fd: -1,
            errno: Some(ENOSYS | EOPNOTSUPP),
        }
    )
}
