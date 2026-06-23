// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! SCM_RIGHTS fd-passing tests over Unix domain sockets.

use std::ffi::CStr;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::handlers::{HandlerCtx, HandlerError, HandlerToken};
use crate::os::eventfd::EventFd;
use crate::os::unix_socket::{UnixListener, UnixStream};
use crate::register_handler;

use super::TestOutcome;
use super::agents::{AgentHandle, AgentName};
use super::registry::Registry;
use super::run_context::RunContext;

#[derive(Clone, Copy)]
struct ScmPair {
    sender: AgentName,
    receiver: AgentName,
}

const SCM_PAIRS: &[ScmPair] = &[
    ScmPair {
        // PIE-glibc → PIE-glibc, sibling subtree (baseline).
        sender: AgentName::Dpg1,
        receiver: AgentName::Dpg2,
    },
    ScmPair {
        // PIE-glibc → PIE-glibc, depth-2 (fd routes through one
        // hop on each side — exercises the bridge-fd inheritance).
        sender: AgentName::Dpg1Dpg1,
        receiver: AgentName::Dpg2Dpg,
    },
    // Cross-binary-type pairs. The shim's fd-bridge / replacement
    // table is driven by the parent's binary type; passing fds
    // across processes with different binary types exercises code
    // paths that same-type pairs do not.
    ScmPair {
        // PIE-glibc → non-PIE-glibc: the sshd→bash class fd passing
        // (every common Unix tool inherits an fd from its launcher).
        sender: AgentName::Dpg1,
        receiver: AgentName::Dpg1Dng,
    },
    ScmPair {
        // non-PIE-glibc → PIE-glibc: the reverse direction. Useful
        // because the receiver-side bridge install path differs
        // from the sender-side.
        sender: AgentName::Dpg1Dng,
        receiver: AgentName::Dpg1,
    },
    ScmPair {
        // non-PIE → non-PIE (the bash→bash recursion in VS Code).
        sender: AgentName::Dpg1Dng,
        receiver: AgentName::Dpg1DngDng,
    },
    ScmPair {
        // non-PIE → static-PIE-musl (the bash→cli VS Code entry
        // transition). Tests fd-passing across the cli boundary.
        sender: AgentName::Dpg1Dng,
        receiver: AgentName::Dpg1DngSpm,
    },
    ScmPair {
        // static-PIE-musl → non-PIE-glibc (the cli→node VS Code
        // signature transition). The most consequential pair for
        // VS Code Server: every fd Node.js needs (sockets, pipes,
        // pty endpoints) flows through this exact transition.
        sender: AgentName::Dpg1Spm,
        receiver: AgentName::Dpg1SpmDng,
    },
    // Static-PIE-glibc and non-PIE-static-musl coverage. Added so
    // every binary type appears as both sender and receiver at
    // least once. Without these pairs the shim's fd-table install
    // path for static-PIE-glibc and non-PIE-static-musl receivers
    // is never exercised by SCM tests.
    ScmPair {
        // static-PIE-glibc as sender (cross-tree): exercises the
        // sender-side passed_fds path on a static-PIE-glibc binary.
        sender: AgentName::Dpg1Spg,
        receiver: AgentName::Dpg2,
    },
    ScmPair {
        // non-PIE-static-musl as sender (cross-tree): exercises the
        // sender-side passed_fds path on a fully static musl binary.
        sender: AgentName::Dpg1Snm,
        receiver: AgentName::Dpg2,
    },
    ScmPair {
        // PIE-glibc → static-PIE-glibc within-tree: the receiver-side
        // fd-table install path on static-PIE-glibc (which still loads
        // ld.so for nss/dlopen but has fixed-load semantics).
        sender: AgentName::Dpg1,
        receiver: AgentName::Dpg1Spg,
    },
];

#[derive(Clone, Copy)]
struct ScmScenario {
    name: &'static str,
    kind: ScmKind,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ScmKind {
    PassEventfd,
    PassEventfdPollWake,
    PassTcpSocket,
    PassTcpAccepted,
    PassUnixSocketpair,
    PassPty,
    PassThenCloseSender,
    PassTwoFdsOneMsg,
    /// Originally designed as a HypB probe for the broker
    /// `SubscriptionList`'s "deferred-edge-bit orphaned after
    /// producer quiesce" failure mode. Sender creates a pipe,
    /// passes the read end via SCM_RIGHTS, writes two bytes
    /// back-to-back so the broker's second `notify(IN)` lands
    /// while the first edge-frame is still in flight (forcing
    /// the deferred-bit code path). Receiver does two
    /// `epoll_wait + read(1)` cycles — level-triggered usage
    /// where the second wake must arrive even with no further
    /// producer activity. Native Linux: trivially PASS.
    ///
    /// **In practice this probe currently exercises PE.5, not
    /// HypB.** Investigation 2026-06-03 (post merge `8c8bf696`):
    /// the agent dies during SCM teardown with a tokio I/O driver
    /// EIO panic *before* reaching the wake-2 path. Captured
    /// `/tmp/rst-diag.log` shows:
    ///   [PE.5-diag] BROKER PROTOCOL VIOLATION
    ///     Release handle_id=N caller_pid=P
    ///     state_exists=true process_exists=false
    ///   [PE.13-diag] BrokerPipeProvider::release(N) failed:
    ///     io error talking to broker control socket
    ///   [PE.5-diag] broker eventfd Io fallthrough: BrokenPipe
    /// Tokio's wake `eventfd_write` fails because the broker
    /// control socket got torn down after the Release-with-
    /// process_exists=false protocol violation; tokio panics
    /// in `runtime/io/driver.rs:260` and the coordinator times
    /// out reading the agent's result line.
    ///
    /// Until PE.5 (the release-after-deregister bug) is fixed,
    /// this probe is effectively a deterministic PE.5 repro
    /// across all 10 SCM_PAIRS combos. Once PE.5 is fixed, it
    /// reverts to validating HypB (PASS if the flush wiring
    /// in `8c8bf696` is correct, FAIL at wake-2 otherwise).
    /// A separate non-tokio probe will isolate HypB cleanly.
    PassPipeDoubleWake,
}

const SCM_SCENARIOS: &[ScmScenario] = &[
    ScmScenario {
        name: "pass_eventfd",
        kind: ScmKind::PassEventfd,
    },
    ScmScenario {
        name: "pass_eventfd_poll_wake",
        kind: ScmKind::PassEventfdPollWake,
    },
    ScmScenario {
        name: "pass_tcp_socket",
        kind: ScmKind::PassTcpSocket,
    },
    ScmScenario {
        name: "pass_tcp_accepted",
        kind: ScmKind::PassTcpAccepted,
    },
    ScmScenario {
        name: "pass_unix_socketpair",
        kind: ScmKind::PassUnixSocketpair,
    },
    ScmScenario {
        name: "pass_pty",
        kind: ScmKind::PassPty,
    },
    ScmScenario {
        name: "pass_then_close_sender",
        kind: ScmKind::PassThenCloseSender,
    },
    ScmScenario {
        name: "pass_two_fds_one_msg",
        kind: ScmKind::PassTwoFdsOneMsg,
    },
    ScmScenario {
        name: "pass_pipe_double_wake",
        kind: ScmKind::PassPipeDoubleWake,
    },
];

#[derive(Serialize, Deserialize)]
struct ScmArgs {
    kind: ScmKind,
    socket_path: String,
}

#[derive(Serialize, Deserialize)]
struct ReceiverStartArgs {
    kind: ScmKind,
    socket_path: String,
    result_path: String,
}

#[derive(Serialize, Deserialize)]
struct ReceiverFinishArgs {
    result_path: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ScmOut {
    detail: String,
}

const SCM_RECEIVER: HandlerToken<ScmArgs, ScmOut> = HandlerToken::new("scm_rights.receiver");
const SCM_SENDER: HandlerToken<ScmArgs, ()> = HandlerToken::new("scm_rights.sender");
const SCM_RECEIVER_START: HandlerToken<ReceiverStartArgs, ()> =
    HandlerToken::new("scm_rights.receiver_start");
const SCM_RECEIVER_FINISH: HandlerToken<ReceiverFinishArgs, ScmOut> =
    HandlerToken::new("scm_rights.receiver_finish");
const SCM_SENDER_STAGED: HandlerToken<ScmArgs, ()> = HandlerToken::new("scm_rights.sender_staged");

async fn handle_receiver(args: ScmArgs, ctx: &mut HandlerCtx<'_>) -> Result<ScmOut, HandlerError> {
    let listener = UnixListener::bind(&args.socket_path)?;
    ctx.checkpoint("scm_ready").await?;
    accept_and_validate(args.kind, listener).map_err(HandlerError)
}

async fn handle_sender(args: ScmArgs, ctx: &mut HandlerCtx<'_>) -> Result<(), HandlerError> {
    ctx.checkpoint("scm_ready").await?;
    send_for_scenario(args.kind, &args.socket_path).map_err(HandlerError)
}

async fn handle_receiver_start(
    args: ReceiverStartArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<(), HandlerError> {
    let listener = UnixListener::bind(&args.socket_path)?;
    std::thread::spawn(move || {
        let result = accept_and_validate(args.kind, listener);
        let encoded = serde_json::to_string(&result)
            .unwrap_or_else(|e| format!("{{\"Err\":\"result serialize: {e}\"}}"));
        let _ = std::fs::write(args.result_path, encoded);
    });
    Ok(())
}

async fn handle_sender_staged(
    args: ScmArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<(), HandlerError> {
    send_for_scenario(args.kind, &args.socket_path).map_err(HandlerError)
}

async fn handle_receiver_finish(
    args: ReceiverFinishArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<ScmOut, HandlerError> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match std::fs::read_to_string(&args.result_path) {
            Ok(contents) => {
                let _ = std::fs::remove_file(&args.result_path);
                let decoded: Result<ScmOut, String> = serde_json::from_str(&contents)
                    .map_err(|e| HandlerError(format!("result deserialize: {e}: {contents}")))?;
                return decoded.map_err(HandlerError);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => return Err(HandlerError(format!("read receiver result: {e}"))),
        }
    }
}

pub(crate) fn register_scm_rights_tests(reg: &mut Registry<'_>) {
    register_handler!(SCM_RECEIVER, handle_receiver);
    register_handler!(SCM_SENDER, handle_sender);
    register_handler!(SCM_RECEIVER_START, handle_receiver_start);
    register_handler!(SCM_RECEIVER_FINISH, handle_receiver_finish);
    register_handler!(SCM_SENDER_STAGED, handle_sender_staged);

    for &pair in SCM_PAIRS {
        for scenario in SCM_SCENARIOS {
            let id = format!("SCM.{}.{}_to_{}", scenario.name, pair.sender, pair.receiver);
            let label = format!("{}->{}", pair.sender, pair.receiver);
            let kind = scenario.kind;
            let scenario_name = scenario.name;
            reg.test("vscode", "scm_rights", id)
                .timeout(60)
                .build(move |cx| {
                    let sender = cx.require(pair.sender);
                    let receiver = cx.require(pair.receiver);
                    Box::new(move |run| {
                        let label = label.clone();
                        Box::pin(async move {
                            let result =
                                run_scenario(run, &sender, &receiver, pair, scenario_name, kind)
                                    .await;
                            match result {
                                Ok(detail) => TestOutcome::new(&label, true, detail),
                                Err(detail) => TestOutcome::new(&label, false, detail),
                            }
                        })
                    })
                });
        }
    }
}

async fn run_scenario(
    run: &mut RunContext<'_>,
    sender: &AgentHandle,
    receiver: &AgentHandle,
    pair: ScmPair,
    scenario: &str,
    kind: ScmKind,
) -> Result<String, String> {
    let socket_path = unique_path(scenario, "sock");
    if same_direct_pipe(pair.sender, pair.receiver) {
        run_staged(run, sender, receiver, kind, socket_path).await
    } else {
        let out = run
            .rendezvous_pair(
                receiver,
                &SCM_RECEIVER,
                ScmArgs {
                    kind,
                    socket_path: socket_path.clone(),
                },
                sender,
                &SCM_SENDER,
                ScmArgs { kind, socket_path },
                "scm_ready",
            )
            .await?;
        Ok(out.detail)
    }
}

async fn run_staged(
    run: &mut RunContext<'_>,
    sender: &AgentHandle,
    receiver: &AgentHandle,
    kind: ScmKind,
    socket_path: String,
) -> Result<String, String> {
    let result_path = unique_path("result", "json");
    run.send_named_typed(
        receiver,
        &SCM_RECEIVER_START,
        ReceiverStartArgs {
            kind,
            socket_path: socket_path.clone(),
            result_path: result_path.clone(),
        },
    )
    .await
    .map_err(|e| format!("receiver_start: {e}"))?;
    run.send_named_typed(sender, &SCM_SENDER_STAGED, ScmArgs { kind, socket_path })
        .await
        .map_err(|e| format!("sender_staged: {e}"))?;
    let out = run
        .send_named_typed(
            receiver,
            &SCM_RECEIVER_FINISH,
            ReceiverFinishArgs { result_path },
        )
        .await
        .map_err(|e| format!("receiver_finish: {e}"))?;
    Ok(out.detail)
}

fn same_direct_pipe(left: AgentName, right: AgentName) -> bool {
    direct_pipe(left) == direct_pipe(right)
}

fn direct_pipe(agent: AgentName) -> AgentName {
    agent.ancestors().first().copied().unwrap_or(agent)
}

fn unique_path(scenario: &str, ext: &str) -> String {
    format!(
        "/run/litebox-scm-{}-{scenario}-{}.{}",
        std::process::id(),
        monotonic_suffix(),
        ext
    )
}

fn monotonic_suffix() -> u64 {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

fn accept_and_validate(kind: ScmKind, listener: UnixListener) -> Result<ScmOut, String> {
    let stream = listener.accept()?;
    match kind {
        ScmKind::PassEventfd => receive_eventfd(stream, 7, false, "eventfd"),
        ScmKind::PassEventfdPollWake => receive_eventfd_poll_wake(stream),
        ScmKind::PassTcpSocket => receive_tcp(stream),
        ScmKind::PassTcpAccepted => receive_tcp_accepted(stream),
        ScmKind::PassUnixSocketpair => receive_unix_socketpair(stream),
        ScmKind::PassPty => receive_pty(stream),
        ScmKind::PassThenCloseSender => receive_eventfd(stream, 5, true, "close_sender"),
        ScmKind::PassTwoFdsOneMsg => receive_two_eventfds(stream),
        ScmKind::PassPipeDoubleWake => receive_pipe_double_wake(stream),
    }
}

fn send_for_scenario(kind: ScmKind, socket_path: &str) -> Result<(), String> {
    match kind {
        ScmKind::PassEventfd => {
            let ev = EventFd::open(0, "nonblock|cloexec").map_err(|e| e.to_string())?;
            let stream = UnixStream::connect(socket_path)?;
            stream.send_fd(ev.as_fd(), b"eventfd")?;
            ev.write(7).map_err(|e| e.to_string())?;
            Ok(())
        }
        ScmKind::PassEventfdPollWake => {
            let ev = EventFd::open(0, "nonblock|cloexec").map_err(|e| e.to_string())?;
            let stream = UnixStream::connect(socket_path)?;
            stream.send_fd(ev.as_fd(), b"eventfd_poll_wake")?;
            // Wait for receiver to confirm fast epoll_wait(0) returned no
            // events (READY sentinel = single 'R' byte).
            let mut sentinel = [0u8; 1];
            stream.read_exact(&mut sentinel)?;
            if sentinel[0] != b'R' {
                return Err(format!(
                    "poll_wake: bad READY sentinel {:?}",
                    sentinel[0] as char
                ));
            }
            // Now write to the eventfd; the receiver's epoll_wait(2000ms)
            // should observe IN promptly.
            ev.write(7).map_err(|e| e.to_string())?;
            Ok(())
        }
        ScmKind::PassTcpSocket => send_tcp(socket_path),
        ScmKind::PassTcpAccepted => send_tcp_accepted(socket_path),
        ScmKind::PassUnixSocketpair => send_unix_socketpair(socket_path),
        ScmKind::PassPty => send_pty(socket_path),
        ScmKind::PassThenCloseSender => {
            let ev = EventFd::open(0, "nonblock|cloexec").map_err(|e| e.to_string())?;
            let source_fd = ev.as_raw_fd();
            let stream = UnixStream::connect(socket_path)?;
            stream.send_fd(ev.as_fd(), b"close_sender")?;
            drop(ev);
            if fd_is_open(source_fd) {
                return Err(format!("source eventfd {source_fd} still open after drop"));
            }
            Ok(())
        }
        ScmKind::PassTwoFdsOneMsg => {
            let first = EventFd::open(0, "nonblock|cloexec").map_err(|e| e.to_string())?;
            let second = EventFd::open(0, "nonblock|cloexec").map_err(|e| e.to_string())?;
            let stream = UnixStream::connect(socket_path)?;
            stream.send_fds(&[first.as_fd(), second.as_fd()], b"two_eventfds")?;
            first.write(11).map_err(|e| e.to_string())?;
            second.write(13).map_err(|e| e.to_string())?;
            Ok(())
        }
        ScmKind::PassPipeDoubleWake => send_pipe_double_wake(socket_path),
    }
}

fn receive_eventfd(
    stream: UnixStream,
    expected: u64,
    write_received: bool,
    expected_payload: &str,
) -> Result<ScmOut, String> {
    let (fd, payload) = stream.recv_fd(64)?;
    expect_payload(&payload, expected_payload)?;
    let ev = eventfd_from_received(fd);
    if write_received {
        ev.write(expected).map_err(|e| e.to_string())?;
    }
    let value = ev.read().map_err(|e| e.to_string())?;
    if value != expected {
        return Err(format!("expected eventfd value {expected}, got {value}"));
    }
    Ok(ScmOut {
        detail: format!("received_eventfd_fd={} value={value}", ev.as_raw_fd()),
    })
}

fn receive_eventfd_poll_wake(stream: UnixStream) -> Result<ScmOut, String> {
    let (fd, payload) = stream.recv_fd(64)?;
    expect_payload(&payload, "eventfd_poll_wake")?;
    let ev = eventfd_from_received(fd);
    let mut epoll = crate::os::epoll::Epoll::new().map_err(|e| format!("epoll_create1: {e}"))?;
    epoll
        .add_fd(
            ev.as_raw_fd(),
            "in",
            crate::os::epoll::EpollTarget {
                kind: "eventfd",
                id: ev.as_raw_fd() as u64,
            },
        )
        .map_err(|e| format!("epoll_ctl add eventfd: {e}"))?;
    // Step 4: fast poll (timeout=0) should report no events.
    let pre = epoll
        .wait(0, 4)
        .map_err(|e| format!("pre epoll_wait: {e}"))?;
    if !pre.is_empty() {
        return Err(format!("pre epoll_wait(0) expected no events, got {pre:?}"));
    }
    // Tell sender to write.
    stream.write_all(b"R")?;
    // Step 6: wait up to 2s for the sender's write to wake us.
    let started = std::time::Instant::now();
    let post = epoll
        .wait(2000, 4)
        .map_err(|e| format!("post epoll_wait: {e}"))?;
    let elapsed_ms = started.elapsed().as_millis();
    if post.is_empty() {
        return Err(format!(
            "post epoll_wait(2000) timed out without IN ({elapsed_ms}ms elapsed)"
        ));
    }
    // Drain the eventfd so the post-test state is clean.
    let value = ev.read().map_err(|e| e.to_string())?;
    Ok(ScmOut {
        detail: format!("poll_wake_received={value} events={post:?} wake_ms={elapsed_ms}"),
    })
}

fn receive_two_eventfds(stream: UnixStream) -> Result<ScmOut, String> {
    let (fds, payload) = stream.recv_fds(64, 2)?;
    expect_payload(&payload, "two_eventfds")?;
    if fds.len() != 2 {
        return Err(format!("expected 2 eventfds, got {}", fds.len()));
    }
    let mut iter = fds.into_iter();
    let first = eventfd_from_received(iter.next().expect("len checked"));
    let second = eventfd_from_received(iter.next().expect("len checked"));
    let first_value = first.read().map_err(|e| e.to_string())?;
    let second_value = second.read().map_err(|e| e.to_string())?;
    if first_value != 11 || second_value != 13 {
        return Err(format!(
            "expected eventfd values 11,13 got {first_value},{second_value}"
        ));
    }
    Ok(ScmOut {
        detail: format!(
            "received_eventfds=[{},{}] values=11,13",
            first.as_raw_fd(),
            second.as_raw_fd()
        ),
    })
}

// ---------- pass_pipe_double_wake ----------
//
// HypB probe. Documented in detail on `ScmKind::PassPipeDoubleWake`.
//
// Wire protocol on the unix stream (over the SCM_RIGHTS path):
//   sender -> receiver: SCM_RIGHTS msg with pipe-read fd + b"pipe_dwake"
//   receiver -> sender: b"R"     ("receiver ready, both ends armed")
//   sender  -> receiver: b"B"    ("both bytes written, do not close")
//   receiver -> sender: b"D"     ("done validating, you can exit")
// The sender holds the write end open across the two `write(1)` calls
// AND across the receiver's two `epoll_wait` cycles, so the only
// notification activity is the back-to-back `notify(IN)` pair. There
// is no follow-up HUP that would otherwise re-flush a deferred bit.

fn send_pipe_double_wake(socket_path: &str) -> Result<(), String> {
    let mut pipe_fds = [0i32; 2];
    // SAFETY: pipe2 writes two valid fds on success; size is 2.
    let rc = unsafe { libc::pipe2(pipe_fds.as_mut_ptr(), libc::O_CLOEXEC) };
    if rc != 0 {
        return Err(format!("pipe2: {}", std::io::Error::last_os_error()));
    }
    // SAFETY: each fd was just produced by pipe2 and is uniquely owned here.
    let read_end = unsafe { OwnedFd::from_raw_fd(pipe_fds[0]) };
    // SAFETY: write end fd ownership transferred.
    let write_end = unsafe { OwnedFd::from_raw_fd(pipe_fds[1]) };

    let stream = UnixStream::connect(socket_path)?;
    stream.send_fd(read_end.as_fd(), b"pipe_dwake")?;
    drop(read_end);

    // Wait for receiver to confirm it has subscribed.
    let mut ready = [0u8; 1];
    stream.read_exact(&mut ready)?;
    if ready[0] != b'R' {
        return Err(format!(
            "expected READY sentinel 'R', got {:?}",
            ready[0] as char
        ));
    }

    // Back-to-back writes. The broker's `notify(IN)` for the second
    // write should land while the first edge frame is still
    // in-flight, exercising the defer path. We do NOT delay between
    // them and we do NOT close the write end after — both deliberate.
    write_all(write_end.as_raw_fd(), b"x")?;
    write_all(write_end.as_raw_fd(), b"y")?;
    stream.write_all(b"B")?;

    // Wait for receiver to finish before dropping the write end (so
    // the receiver's epoll loop never observes HUP, which would
    // separately re-flush the deferred bit and mask the bug).
    let mut done = [0u8; 1];
    stream.read_exact(&mut done)?;
    if done[0] != b'D' {
        return Err(format!(
            "expected DONE sentinel 'D', got {:?}",
            done[0] as char
        ));
    }
    drop(write_end);
    Ok(())
}

fn receive_pipe_double_wake(stream: UnixStream) -> Result<ScmOut, String> {
    let (fd, payload) = stream.recv_fd(64)?;
    expect_payload(&payload, "pipe_dwake")?;
    let read_fd = fd.as_raw_fd();

    let mut epoll = crate::os::epoll::Epoll::new().map_err(|e| format!("epoll_create1: {e}"))?;
    epoll
        .add_fd(
            read_fd,
            "in",
            crate::os::epoll::EpollTarget {
                kind: "pipe_read",
                id: read_fd as u64,
            },
        )
        .map_err(|e| format!("epoll_ctl add pipe read end: {e}"))?;

    // Pre-check: with nothing written, fast poll should be empty.
    let pre = epoll
        .wait(0, 4)
        .map_err(|e| format!("pre epoll_wait: {e}"))?;
    if !pre.is_empty() {
        return Err(format!("pre epoll_wait(0) expected no events, got {pre:?}"));
    }
    stream.write_all(b"R")?;

    // Wait for the sender's "both bytes written" sentinel so we know
    // both `notify(IN)` calls have landed at the broker before we
    // start consuming.
    let mut both = [0u8; 1];
    stream.read_exact(&mut both)?;
    if both[0] != b'B' {
        return Err(format!(
            "expected BOTH sentinel 'B', got {:?}",
            both[0] as char
        ));
    }

    // Wake 1: should arrive promptly carrying the first byte.
    let started_1 = Instant::now();
    let evs_1 = epoll
        .wait(2000, 4)
        .map_err(|e| format!("wake1 epoll_wait: {e}"))?;
    let elapsed_1_ms = started_1.elapsed().as_millis();
    if evs_1.is_empty() {
        return Err(format!(
            "wake1 epoll_wait(2000) timed out without IN ({elapsed_1_ms}ms elapsed) — \
             notification path did not deliver the first write"
        ));
    }
    let byte_1 = read_exact(read_fd, 1)?;
    if byte_1 != b"x" {
        return Err(format!("wake1 read: expected 'x', got {:?}", byte_1));
    }

    // Wake 2: requires the broker's deferred IN bit (queued during
    // the back-to-back write pair) to be re-emitted. On native Linux
    // pipe epoll is level-triggered and trivially re-fires while data
    // remains. On litebox, the broker `SubscriptionList`'s
    // `try_flush_subscriptions` has no production call site, so the
    // deferred bit is orphaned — this `epoll_wait` blocks until
    // timeout.
    let started_2 = Instant::now();
    let evs_2 = epoll
        .wait(2000, 4)
        .map_err(|e| format!("wake2 epoll_wait: {e}"))?;
    let elapsed_2_ms = started_2.elapsed().as_millis();
    if evs_2.is_empty() {
        // Send DONE so the sender does not block forever before we
        // surface the error.
        let _ = stream.write_all(b"D");
        return Err(format!(
            "wake2 epoll_wait(2000) timed out without IN \
             ({elapsed_1_ms}ms wake1, {elapsed_2_ms}ms wake2) — \
             deferred-edge bit orphaned (HypB)"
        ));
    }
    let byte_2 = read_exact(read_fd, 1)?;
    if byte_2 != b"y" {
        let _ = stream.write_all(b"D");
        return Err(format!("wake2 read: expected 'y', got {:?}", byte_2));
    }

    stream.write_all(b"D")?;
    Ok(ScmOut {
        detail: format!(
            "pipe_dwake ok wake1={elapsed_1_ms}ms wake2={elapsed_2_ms}ms \
             evs1={evs_1:?} evs2={evs_2:?}"
        ),
    })
}

fn send_unix_socketpair(socket_path: &str) -> Result<(), String> {
    let (passed_end, peer_end) = unix_socketpair()?;
    let stream = UnixStream::connect(socket_path)?;
    stream.send_fd(passed_end.as_fd(), b"unix_socketpair")?;
    drop(passed_end);

    let ping = read_exact(peer_end.as_raw_fd(), b"SCM_USP_PING".len())?;
    if ping != b"SCM_USP_PING" {
        return Err(format!(
            "unix socketpair peer read mismatch: {:?}",
            String::from_utf8_lossy(&ping)
        ));
    }
    write_all(peer_end.as_raw_fd(), b"SCM_USP_PONG")?;
    Ok(())
}

fn receive_unix_socketpair(stream: UnixStream) -> Result<ScmOut, String> {
    let (fd, payload) = stream.recv_fd(64)?;
    expect_payload(&payload, "unix_socketpair")?;
    let raw = fd.as_raw_fd();
    write_all(raw, b"SCM_USP_PING")?;
    let pong = read_exact(raw, b"SCM_USP_PONG".len())?;
    if pong != b"SCM_USP_PONG" {
        return Err(format!(
            "unix socketpair echo mismatch: {:?}",
            String::from_utf8_lossy(&pong)
        ));
    }
    Ok(ScmOut {
        detail: format!("received_unix_socketpair_fd={raw} bidi=ok"),
    })
}

fn unix_socketpair() -> Result<(OwnedFd, OwnedFd), String> {
    let mut fds = [0i32; 2];
    // SAFETY: fds points to space for two raw fds; socketpair initializes both on success.
    let rc = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    };
    if rc != 0 {
        return Err(format!("socketpair: {}", std::io::Error::last_os_error()));
    }
    // SAFETY: socketpair returned two fresh, uniquely-owned fds.
    let first = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    // SAFETY: socketpair returned two fresh, uniquely-owned fds.
    let second = unsafe { OwnedFd::from_raw_fd(fds[1]) };
    Ok((first, second))
}

fn send_pty(socket_path: &str) -> Result<(), String> {
    let (master, slave) = open_pty_pair()?;
    make_raw(slave.as_raw_fd())?;
    let stream = UnixStream::connect(socket_path)?;
    stream.send_fd(master.as_fd(), b"pty")?;

    let ping = read_exact(slave.as_raw_fd(), b"SCM_PTY_PING".len())?;
    if ping != b"SCM_PTY_PING" {
        return Err(format!(
            "pty slave read mismatch: {:?}",
            String::from_utf8_lossy(&ping)
        ));
    }
    write_all(slave.as_raw_fd(), b"SCM_PTY_PONG")?;
    Ok(())
}

fn receive_pty(stream: UnixStream) -> Result<ScmOut, String> {
    let (fd, payload) = stream.recv_fd(64)?;
    expect_payload(&payload, "pty")?;
    let raw = fd.as_raw_fd();
    let mut pty_num = 0u32;
    // SAFETY: TIOCGPTN writes a u32 to the provided pointer for a PTY master fd.
    let rc = unsafe { libc::ioctl(raw, libc::TIOCGPTN, std::ptr::addr_of_mut!(pty_num)) };
    if rc != 0 {
        return Err(format!(
            "received pty TIOCGPTN: {}",
            std::io::Error::last_os_error()
        ));
    }
    write_all(raw, b"SCM_PTY_PING")?;
    let pong = read_exact(raw, b"SCM_PTY_PONG".len())?;
    if pong != b"SCM_PTY_PONG" {
        return Err(format!(
            "pty master read mismatch: {:?}",
            String::from_utf8_lossy(&pong)
        ));
    }
    Ok(ScmOut {
        detail: format!("received_pty_master_fd={raw} pty_num={pty_num} bidi=ok"),
    })
}

fn open_pty_pair() -> Result<(OwnedFd, OwnedFd), String> {
    // SAFETY: posix_openpt returns a fresh fd on success.
    let master_raw = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC) };
    if master_raw < 0 {
        return Err(format!("posix_openpt: {}", std::io::Error::last_os_error()));
    }
    // SAFETY: master_raw was just returned by posix_openpt and is uniquely owned.
    let master = unsafe { OwnedFd::from_raw_fd(master_raw) };
    // SAFETY: grantpt/unlockpt operate on a live PTY master fd.
    if unsafe { libc::grantpt(master.as_raw_fd()) } != 0 {
        return Err(format!("grantpt: {}", std::io::Error::last_os_error()));
    }
    // SAFETY: grantpt/unlockpt operate on a live PTY master fd.
    if unsafe { libc::unlockpt(master.as_raw_fd()) } != 0 {
        return Err(format!("unlockpt: {}", std::io::Error::last_os_error()));
    }

    let mut name = [0i8; 128];
    // SAFETY: name is a valid writable buffer and master is a live PTY master fd.
    let pts_rc = unsafe { libc::ptsname_r(master.as_raw_fd(), name.as_mut_ptr(), name.len()) };
    if pts_rc != 0 {
        return Err(format!(
            "ptsname_r: {}",
            std::io::Error::from_raw_os_error(pts_rc)
        ));
    }
    // SAFETY: ptsname_r wrote a NUL-terminated C string into name on success.
    let slave_path = unsafe { CStr::from_ptr(name.as_ptr()) };
    // SAFETY: open creates a fresh fd on success and does not retain slave_path.
    let slave_raw = unsafe {
        libc::open(
            slave_path.as_ptr(),
            libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC,
        )
    };
    if slave_raw < 0 {
        return Err(format!("open slave: {}", std::io::Error::last_os_error()));
    }
    // SAFETY: slave_raw was just returned by open and is uniquely owned.
    let slave = unsafe { OwnedFd::from_raw_fd(slave_raw) };
    Ok((master, slave))
}

fn make_raw(fd: i32) -> Result<(), String> {
    // SAFETY: zeroed termios is immediately overwritten by tcgetattr on success.
    let mut tio = unsafe { std::mem::zeroed::<libc::termios>() };
    // SAFETY: tcgetattr writes termios for a live terminal fd.
    if unsafe { libc::tcgetattr(fd, std::ptr::addr_of_mut!(tio)) } != 0 {
        return Err(format!("tcgetattr: {}", std::io::Error::last_os_error()));
    }
    // SAFETY: cfmakeraw mutates the initialized termios struct in place.
    unsafe { libc::cfmakeraw(std::ptr::addr_of_mut!(tio)) };
    // SAFETY: tcsetattr reads the initialized termios struct.
    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, std::ptr::addr_of!(tio)) } != 0 {
        return Err(format!("tcsetattr: {}", std::io::Error::last_os_error()));
    }
    Ok(())
}

fn send_tcp(socket_path: &str) -> Result<(), String> {
    let listener = tcp_listener()?;
    let port = listener_port(listener.as_raw_fd())?;
    std::thread::spawn(move || {
        let _ = tcp_echo_once(listener);
    });
    let conn = tcp_connect(port)?;
    let stream = UnixStream::connect(socket_path)?;
    stream.send_fd(conn.as_fd(), b"tcp")?;
    Ok(())
}

fn receive_tcp(stream: UnixStream) -> Result<ScmOut, String> {
    let (fd, payload) = stream.recv_fd(64)?;
    expect_payload(&payload, "tcp")?;
    let raw = fd.as_raw_fd();
    let payload = b"SCM_TCP_PAYLOAD";
    write_all(raw, payload)?;
    let echoed = read_exact(raw, payload.len())?;
    if echoed != payload {
        return Err(format!(
            "tcp echo mismatch: {:?}",
            String::from_utf8_lossy(&echoed)
        ));
    }
    Ok(ScmOut {
        detail: format!("received_tcp_fd={raw} echo=ok"),
    })
}

fn send_tcp_accepted(socket_path: &str) -> Result<(), String> {
    // Mirror the VS Code code-server: listen, let a client connect, accept,
    // SCM-pass the ACCEPTED (server) side, then close our copy. The receiver
    // must be able to write data that reaches the still-open client side.
    let listener = tcp_listener()?;
    let port = listener_port(listener.as_raw_fd())?;
    let client = tcp_connect(port)?;
    let accepted = tcp_accept(listener.as_raw_fd())?;
    let stream = UnixStream::connect(socket_path)?;
    stream.send_fd(accepted.as_fd(), b"tcp_accepted")?;
    drop(accepted);

    // Server->client (the exthost->client keepalive direction): the receiver
    // writes to the accepted socket; we must receive it on the client side.
    let s2c = read_exact(client.as_raw_fd(), b"SCM_ACC_S2C".len())?;
    if s2c != b"SCM_ACC_S2C" {
        return Err(format!(
            "accepted->client delivery failed: {:?}",
            String::from_utf8_lossy(&s2c)
        ));
    }
    // Client->server, for symmetry.
    write_all(client.as_raw_fd(), b"SCM_ACC_C2S")?;
    Ok(())
}

fn receive_tcp_accepted(stream: UnixStream) -> Result<ScmOut, String> {
    let (fd, payload) = stream.recv_fd(64)?;
    expect_payload(&payload, "tcp_accepted")?;
    let raw = fd.as_raw_fd();
    write_all(raw, b"SCM_ACC_S2C")?;
    let c2s = read_exact(raw, b"SCM_ACC_C2S".len())?;
    if c2s != b"SCM_ACC_C2S" {
        return Err(format!(
            "client->accepted mismatch: {:?}",
            String::from_utf8_lossy(&c2s)
        ));
    }
    Ok(ScmOut {
        detail: format!("received_accepted_fd={raw} bidi=ok"),
    })
}

fn tcp_accept(listener: i32) -> Result<OwnedFd, String> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        // SAFETY: accept4 operates on the live listener fd and returns a fresh fd.
        let raw = unsafe {
            libc::accept4(
                listener,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                libc::SOCK_CLOEXEC,
            )
        };
        if raw >= 0 {
            // SAFETY: raw was just returned by accept4 and is uniquely owned here.
            return Ok(unsafe { OwnedFd::from_raw_fd(raw) });
        }
        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::EINTR) => {}
            Some(libc::EAGAIN) | Some(libc::EWOULDBLOCK)
                if std::time::Instant::now() < deadline =>
            {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            _ => return Err(format!("tcp accept: {err}")),
        }
    }
}

fn tcp_listener() -> Result<OwnedFd, String> {
    // SAFETY: socket creates a fresh fd on success.
    let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if raw < 0 {
        return Err(format!("tcp socket: {}", std::io::Error::last_os_error()));
    }
    // SAFETY: raw was just returned by socket and is uniquely owned here.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let one: libc::c_int = 1;
    // SAFETY: setsockopt reads `one` and does not take ownership of fd.
    let _ = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            std::ptr::addr_of!(one).cast(),
            std::mem::size_of_val(&one) as libc::socklen_t,
        )
    };
    let addr = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: libc::INADDR_LOOPBACK.to_be(),
        },
        sin_zero: [0; 8],
    };
    // SAFETY: addr points to a valid IPv4 sockaddr and fd is a live TCP socket.
    let rc = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            std::ptr::addr_of!(addr).cast::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(format!("tcp bind: {}", std::io::Error::last_os_error()));
    }
    // SAFETY: fd is a live bound TCP socket.
    if unsafe { libc::listen(fd.as_raw_fd(), 1) } != 0 {
        return Err(format!("tcp listen: {}", std::io::Error::last_os_error()));
    }
    Ok(fd)
}

fn listener_port(fd: i32) -> Result<u16, String> {
    // SAFETY: zeroed sockaddr_in is an output buffer for getsockname.
    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    // SAFETY: addr/len are writable and fd is a live socket.
    if unsafe {
        libc::getsockname(
            fd,
            std::ptr::addr_of_mut!(addr).cast::<libc::sockaddr>(),
            &mut len,
        )
    } != 0
    {
        return Err(format!("getsockname: {}", std::io::Error::last_os_error()));
    }
    Ok(u16::from_be(addr.sin_port))
}

fn tcp_connect(port: u16) -> Result<OwnedFd, String> {
    // SAFETY: socket creates a fresh fd on success.
    let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if raw < 0 {
        return Err(format!("tcp socket: {}", std::io::Error::last_os_error()));
    }
    // SAFETY: raw was just returned by socket and is uniquely owned here.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let addr = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: port.to_be(),
        sin_addr: libc::in_addr {
            s_addr: libc::INADDR_LOOPBACK.to_be(),
        },
        sin_zero: [0; 8],
    };
    // SAFETY: addr points to a valid IPv4 sockaddr and fd is a live TCP socket.
    let rc = unsafe {
        libc::connect(
            fd.as_raw_fd(),
            std::ptr::addr_of!(addr).cast::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(format!("tcp connect: {}", std::io::Error::last_os_error()));
    }
    Ok(fd)
}

fn tcp_echo_once(listener: OwnedFd) -> Result<(), String> {
    let accepted = loop {
        // SAFETY: accept4 operates on the live listener fd and returns a fresh fd on success.
        let raw = unsafe {
            libc::accept4(
                listener.as_raw_fd(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                libc::SOCK_CLOEXEC,
            )
        };
        if raw >= 0 {
            // SAFETY: raw was just returned by accept4 and is uniquely owned here.
            break unsafe { OwnedFd::from_raw_fd(raw) };
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EINTR) {
            return Err(format!("tcp accept: {err}"));
        }
    };
    let mut buf = [0u8; 4096];
    loop {
        let n = read_some(accepted.as_raw_fd(), &mut buf)?;
        if n == 0 {
            return Ok(());
        }
        write_all(accepted.as_raw_fd(), &buf[..n])?;
    }
}

fn read_some(fd: i32, buf: &mut [u8]) -> Result<usize, String> {
    loop {
        // SAFETY: buf is writable and fd is a live descriptor.
        let rc = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        if rc >= 0 {
            return Ok(rc as usize);
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EINTR) {
            return Err(format!("read fd {fd}: {err}"));
        }
    }
}

fn read_exact(fd: i32, len: usize) -> Result<Vec<u8>, String> {
    let mut out = vec![0u8; len];
    let mut offset = 0;
    while offset < len {
        let n = read_some(fd, &mut out[offset..])?;
        if n == 0 {
            return Err(format!("read fd {fd}: EOF after {offset}/{len} bytes"));
        }
        offset += n;
    }
    Ok(out)
}

fn write_all(fd: i32, mut data: &[u8]) -> Result<(), String> {
    while !data.is_empty() {
        // SAFETY: data is readable and fd is a live descriptor.
        let rc = unsafe { libc::write(fd, data.as_ptr().cast(), data.len()) };
        if rc > 0 {
            data = &data[rc as usize..];
            continue;
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EINTR) {
            return Err(format!("write fd {fd}: {err}"));
        }
    }
    Ok(())
}

fn fd_is_open(fd: i32) -> bool {
    // SAFETY: F_GETFD inspects descriptor state and does not take ownership.
    (unsafe { libc::fcntl(fd, libc::F_GETFD) }) >= 0
}

fn expect_payload(actual: &[u8], expected: &str) -> Result<(), String> {
    if actual == expected.as_bytes() {
        Ok(())
    } else {
        Err(format!(
            "payload mismatch: expected {expected:?}, got {:?}",
            String::from_utf8_lossy(actual)
        ))
    }
}

fn eventfd_from_received(fd: OwnedFd) -> EventFd {
    EventFd::from_owned_fd(fd, 0)
}
