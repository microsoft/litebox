// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! AF_UNIX SOCK_STREAM socketpair probes for broker-backed pairs.
//!
//! Native Linux is the gold standard.

use serde::{Deserialize, Serialize};

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use crate::handlers::{HandlerCtx, HandlerError, HandlerToken};
use crate::{BinaryType, register_handler, register_leaf_subcommand};

use super::TestOutcome;
use super::agents::AgentName;
use super::registry::Registry;

const RUN: HandlerToken<ProbeArgs, ProbeOut> = HandlerToken::new("uds_stream.run");

const PAYLOAD_PARENT: &[u8] = b"uds-stream-parent-to-child";
const PAYLOAD_CHILD: &[u8] = b"uds-stream-child-to-parent";
const POLL_TIMEOUT_MS: i32 = 5_000;

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
enum Scenario {
    Peer0ToPeer1,
    Peer1ToPeer0,
    EofPeer0ToPeer1,
    ShutdownPeer0ToPeer1,
    ParentToChild,
    ChildToParent,
    ParentEofChild,
    ParentShutdownChild,
}

impl Scenario {
    const NONFORK: [Self; 4] = [
        Self::Peer0ToPeer1,
        Self::Peer1ToPeer0,
        Self::EofPeer0ToPeer1,
        Self::ShutdownPeer0ToPeer1,
    ];
    const FORK: [Self; 4] = [
        Self::ParentToChild,
        Self::ChildToParent,
        Self::ParentEofChild,
        Self::ParentShutdownChild,
    ];

    const fn label(self) -> &'static str {
        match self {
            Self::Peer0ToPeer1 => "peer0_to_peer1",
            Self::Peer1ToPeer0 => "peer1_to_peer0",
            Self::EofPeer0ToPeer1 => "eof_peer0_to_peer1",
            Self::ShutdownPeer0ToPeer1 => "shutdown_peer0_to_peer1",
            Self::ParentToChild => "parent_to_child",
            Self::ChildToParent => "child_to_parent",
            Self::ParentEofChild => "parent_eof_child",
            Self::ParentShutdownChild => "parent_shutdown_child",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
enum InheritVariant {
    Inline,
    ForkExecPie,
    ForkExecNonPie,
}

impl InheritVariant {
    const fn label(self) -> &'static str {
        match self {
            Self::Inline => "inline",
            Self::ForkExecPie => "fork_exec_pie",
            Self::ForkExecNonPie => "fork_exec_nonpie",
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct ProbeArgs {
    scenario: Scenario,
    inherit: InheritVariant,
    child_binary: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ProbeOut {
    ok: bool,
    detail: String,
}

pub(crate) fn register_uds_stream_tests(reg: &mut Registry<'_>) {
    register_handler!(RUN, handle_run);
    register_leaf_subcommand!("uds-stream-child", leaf_child::run);

    for scenario in Scenario::NONFORK {
        register_case(reg, scenario, InheritVariant::Inline, None);
    }
    for scenario in Scenario::FORK {
        register_case(
            reg,
            scenario,
            InheritVariant::ForkExecPie,
            Some(BinaryType::PieGlibc),
        );
        register_case(
            reg,
            scenario,
            InheritVariant::ForkExecNonPie,
            Some(BinaryType::NonPieGlibc),
        );
    }
}

fn register_case(
    reg: &mut Registry<'_>,
    scenario: Scenario,
    inherit: InheritVariant,
    child_binary_type: Option<BinaryType>,
) {
    let id = format!("UDS_STREAM.{}.{}", scenario.label(), inherit.label());
    reg.test("vscode", "uds_stream", id)
        .timeout(30)
        .build(move |cx| {
            let agent = cx.require(AgentName::Dpg1);
            Box::new(move |run| {
                Box::pin(async move {
                    let child_binary = child_binary_type.map(|bt| {
                        let self_exe = run.self_exe().to_string();
                        crate::binary_path(bt, &self_exe)
                    });
                    let args = ProbeArgs {
                        scenario,
                        inherit,
                        child_binary,
                    };
                    match run.send_named_typed(&agent, &RUN, args).await {
                        Ok(out) => TestOutcome::new("Dpg1", out.ok, out.detail),
                        Err(e) => TestOutcome::new("Dpg1", false, e),
                    }
                })
            })
        });
}

async fn handle_run(args: ProbeArgs, _ctx: &mut HandlerCtx<'_>) -> Result<ProbeOut, HandlerError> {
    let result = run_probe(&args);
    match result {
        Ok(detail) => Ok(ProbeOut { ok: true, detail }),
        Err(e) => Ok(ProbeOut {
            ok: false,
            detail: e,
        }),
    }
}

fn run_probe(args: &ProbeArgs) -> Result<String, String> {
    match args.inherit {
        InheritVariant::Inline => run_inline(args.scenario),
        InheritVariant::ForkExecPie | InheritVariant::ForkExecNonPie => {
            let child_binary = args
                .child_binary
                .as_deref()
                .ok_or_else(|| "fork_exec probe missing child binary".to_string())?;
            run_fork_exec(args.scenario, child_binary)
        }
    }
}

fn run_inline(scenario: Scenario) -> Result<String, String> {
    let (left, right) = socketpair_stream()?;
    match scenario {
        Scenario::Peer0ToPeer1 => {
            write_all_fd(left.as_raw_fd(), PAYLOAD_PARENT)?;
            read_exact_fd(right.as_raw_fd(), PAYLOAD_PARENT)?;
        }
        Scenario::Peer1ToPeer0 => {
            write_all_fd(right.as_raw_fd(), PAYLOAD_CHILD)?;
            read_exact_fd(left.as_raw_fd(), PAYLOAD_CHILD)?;
        }
        Scenario::EofPeer0ToPeer1 => {
            drop(left);
            expect_eof(right.as_raw_fd())?;
        }
        Scenario::ShutdownPeer0ToPeer1 => {
            shutdown_wr(left.as_raw_fd())?;
            expect_eof(right.as_raw_fd())?;
        }
        Scenario::ParentToChild
        | Scenario::ChildToParent
        | Scenario::ParentEofChild
        | Scenario::ParentShutdownChild => {
            return Err(format!("fork scenario {} used inline", scenario.label()));
        }
    }
    Ok(format!(
        "mode-independent inline socketpair stream scenario={}",
        scenario.label()
    ))
}

fn run_fork_exec(scenario: Scenario, child_binary: &str) -> Result<String, String> {
    let (parent, child_end) = socketpair_stream()?;
    set_cloexec(parent.as_raw_fd(), true)?;
    set_cloexec(child_end.as_raw_fd(), false)?;

    let child_fd = child_end.as_raw_fd();
    let action = match scenario {
        Scenario::ParentToChild => "read-parent-payload",
        Scenario::ChildToParent => "write-child-payload",
        Scenario::ParentEofChild => "expect-eof",
        Scenario::ParentShutdownChild => "expect-eof",
        Scenario::Peer0ToPeer1
        | Scenario::Peer1ToPeer0
        | Scenario::EofPeer0ToPeer1
        | Scenario::ShutdownPeer0ToPeer1 => {
            return Err(format!(
                "inline scenario {} used fork_exec",
                scenario.label()
            ));
        }
    };

    let child = Command::new(child_binary)
        .args(["uds-stream-child", action, &child_fd.to_string()])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn {child_binary}: {e}"))?;
    drop(child_end);

    match scenario {
        Scenario::ParentToChild => {
            write_all_fd(parent.as_raw_fd(), PAYLOAD_PARENT)?;
        }
        Scenario::ChildToParent => {
            read_exact_fd(parent.as_raw_fd(), PAYLOAD_CHILD)?;
        }
        Scenario::ParentEofChild => {
            drop(parent);
        }
        Scenario::ParentShutdownChild => {
            shutdown_wr(parent.as_raw_fd())?;
        }
        Scenario::Peer0ToPeer1
        | Scenario::Peer1ToPeer0
        | Scenario::EofPeer0ToPeer1
        | Scenario::ShutdownPeer0ToPeer1 => unreachable!("validated above"),
    }

    let output = wait_output_timeout(child, Duration::from_secs(6))?;
    expect_child_success(output, action)?;
    Ok(format!(
        "fork_exec socketpair stream scenario={} child={child_binary}",
        scenario.label()
    ))
}

fn socketpair_stream() -> Result<(OwnedFd, OwnedFd), String> {
    let mut fds = [-1; 2];
    // SAFETY: fds points to two valid c_int slots; socketpair initializes both
    // entries on success and returns -1 with errno on failure.
    let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
    if rc != 0 {
        return Err(format!("socketpair(AF_UNIX, SOCK_STREAM): {}", errno()));
    }
    // SAFETY: socketpair succeeded and returned two owned file descriptors.
    let left = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    // SAFETY: socketpair succeeded and returned two owned file descriptors.
    let right = unsafe { OwnedFd::from_raw_fd(fds[1]) };
    Ok((left, right))
}

fn set_cloexec(fd: RawFd, enabled: bool) -> Result<(), String> {
    // SAFETY: fcntl(F_GETFD) reads descriptor flags for the supplied fd.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(format!("fcntl(F_GETFD fd={fd}): {}", errno()));
    }
    let new_flags = if enabled {
        flags | libc::FD_CLOEXEC
    } else {
        flags & !libc::FD_CLOEXEC
    };
    // SAFETY: fcntl(F_SETFD) updates descriptor flags for the supplied fd.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, new_flags) } != 0 {
        return Err(format!("fcntl(F_SETFD fd={fd}): {}", errno()));
    }
    Ok(())
}

fn shutdown_wr(fd: RawFd) -> Result<(), String> {
    // SAFETY: shutdown operates on a live socket fd and does not dereference pointers.
    if unsafe { libc::shutdown(fd, libc::SHUT_WR) } != 0 {
        return Err(format!("shutdown(SHUT_WR fd={fd}): {}", errno()));
    }
    Ok(())
}

fn write_all_fd(fd: RawFd, mut buf: &[u8]) -> Result<(), String> {
    while !buf.is_empty() {
        // SAFETY: buf.as_ptr() is valid for buf.len() bytes for the duration of the call.
        let n = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
        if n < 0 {
            return Err(format!("write(fd={fd}): {}", errno()));
        }
        if n == 0 {
            return Err(format!("write(fd={fd}) returned 0"));
        }
        buf = &buf[n as usize..];
    }
    Ok(())
}

fn read_exact_fd(fd: RawFd, expected: &[u8]) -> Result<(), String> {
    wait_readable(fd)?;
    let mut got = vec![0_u8; expected.len()];
    let mut off = 0;
    while off < got.len() {
        // SAFETY: got[off..] is valid writable memory for the requested length.
        let n = unsafe { libc::read(fd, got[off..].as_mut_ptr().cast(), got.len() - off) };
        if n < 0 {
            return Err(format!("read(fd={fd}): {}", errno()));
        }
        if n == 0 {
            return Err(format!("read(fd={fd}) EOF after {off} bytes"));
        }
        off += n as usize;
    }
    if got != expected {
        return Err(format!(
            "payload mismatch: got={} expected={}",
            String::from_utf8_lossy(&got),
            String::from_utf8_lossy(expected)
        ));
    }
    Ok(())
}

fn expect_eof(fd: RawFd) -> Result<(), String> {
    wait_readable(fd)?;
    let mut byte = [0_u8; 1];
    // SAFETY: byte points to one writable byte for the duration of the call.
    let n = unsafe { libc::read(fd, byte.as_mut_ptr().cast(), byte.len()) };
    if n < 0 {
        return Err(format!("read EOF probe(fd={fd}): {}", errno()));
    }
    if n != 0 {
        return Err(format!("expected EOF on fd={fd}, read {n} byte(s)"));
    }
    Ok(())
}

fn wait_readable(fd: RawFd) -> Result<(), String> {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN | libc::POLLHUP,
        revents: 0,
    };
    // SAFETY: pfd points to one initialized pollfd entry.
    let rc = unsafe { libc::poll(&raw mut pfd, 1, POLL_TIMEOUT_MS) };
    if rc < 0 {
        return Err(format!("poll(fd={fd}): {}", errno()));
    }
    if rc == 0 {
        return Err(format!("poll(fd={fd}) timed out after {POLL_TIMEOUT_MS}ms"));
    }
    if pfd.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) == 0 {
        return Err(format!(
            "poll(fd={fd}) unexpected revents={:#x}",
            pfd.revents
        ));
    }
    Ok(())
}

fn wait_output_timeout(mut child: Child, timeout: Duration) -> Result<Output, String> {
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => {
                return child
                    .wait_with_output()
                    .map_err(|e| format!("wait output: {e}"));
            }
            Ok(None) if start.elapsed() >= timeout => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("child timed out after {}ms", timeout.as_millis()));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
            Err(e) => return Err(format!("try_wait: {e}")),
        }
    }
}

fn expect_child_success(output: Output, action: &str) -> Result<(), String> {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() {
        return Err(format!(
            "child {action} failed status={} stdout={stdout:?} stderr={stderr:?}",
            output.status
        ));
    }
    if !stdout.contains("UDS_STREAM_CHILD_OK") {
        return Err(format!(
            "child {action} missing success marker stdout={stdout:?} stderr={stderr:?}"
        ));
    }
    Ok(())
}

fn errno() -> std::io::Error {
    std::io::Error::last_os_error()
}

mod leaf_child {
    use std::io::Write as _;
    use std::os::fd::RawFd;

    use super::{PAYLOAD_CHILD, PAYLOAD_PARENT, expect_eof, read_exact_fd, write_all_fd};

    pub(super) fn run(args: &[String]) -> i32 {
        match run_inner(args) {
            Ok(detail) => {
                println!("UDS_STREAM_CHILD_OK {detail}");
                0
            }
            Err(e) => {
                let _ = writeln!(std::io::stderr(), "UDS_STREAM_CHILD_ERR {e}");
                1
            }
        }
    }

    fn run_inner(args: &[String]) -> Result<&'static str, String> {
        let action = args
            .get(2)
            .map(String::as_str)
            .ok_or_else(|| "missing child action".to_string())?;
        let fd: RawFd = args
            .get(3)
            .ok_or_else(|| "missing child fd".to_string())?
            .parse()
            .map_err(|e| format!("parse child fd: {e}"))?;
        match action {
            "read-parent-payload" => {
                read_exact_fd(fd, PAYLOAD_PARENT)?;
                Ok("read-parent-payload")
            }
            "write-child-payload" => {
                write_all_fd(fd, PAYLOAD_CHILD)?;
                Ok("write-child-payload")
            }
            "expect-eof" => {
                expect_eof(fd)?;
                Ok("expect-eof")
            }
            other => Err(format!("unknown child action {other}")),
        }
    }
}
