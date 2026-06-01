// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Resource-lifetime (`RL.*`) matrix tests.
//!
//! These scenarios keep broker-backed resources alive across process-exit
//! orderings and compare the sandbox behavior with the native kernel baseline.

use serde::{Deserialize, Serialize};

use crate::handlers::{HandlerCtx, HandlerError, HandlerToken};
use crate::{register_handler, register_leaf_subcommand};

use super::TestOutcome;
use super::agents::{AgentName, SpawnKind};
use super::pipe_bridge::fork_binary_label;
use super::registry::Registry;

const RL_AGENTS: &[AgentName] = &[AgentName::Dpg1, AgentName::Dpg1Dpg1, AgentName::Dpg1Dpg2];
const MARKER: &[u8] = b"RL_PIPE_CHILD_OK";
const PTY_MARKER: &str = "RL_PTY_PEER_OK\r\n";

#[derive(Serialize, Deserialize, Debug)]
struct ChildBinaryArgs {
    child_binary: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct RlOut {
    detail: String,
}

const PIPE_PARENT_EXITS_FIRST: HandlerToken<ChildBinaryArgs, RlOut> =
    HandlerToken::new("resource_lifetime.pipe_parent_exits_first");
const PIPE_CHILD_EXITS_FIRST: HandlerToken<ChildBinaryArgs, RlOut> =
    HandlerToken::new("resource_lifetime.pipe_child_exits_first");
const PIDFD_SUBSCRIBER_EXITS_FIRST: HandlerToken<ChildBinaryArgs, RlOut> =
    HandlerToken::new("resource_lifetime.pidfd_subscriber_exits_first");
const PTY_PEER_CLOSE: HandlerToken<(), RlOut> =
    HandlerToken::new("resource_lifetime.pty_peer_close");

async fn handle_pipe_parent_exits_first(
    args: ChildBinaryArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<RlOut, HandlerError> {
    Ok(RlOut {
        detail: pipe_parent_exits_first(&args.child_binary)?,
    })
}

async fn handle_pipe_child_exits_first(
    args: ChildBinaryArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<RlOut, HandlerError> {
    Ok(RlOut {
        detail: pipe_child_exits_first(&args.child_binary)?,
    })
}

async fn handle_pidfd_subscriber_exits_first(
    args: ChildBinaryArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<RlOut, HandlerError> {
    Ok(RlOut {
        detail: pidfd_subscriber_exits_first(&args.child_binary)?,
    })
}

async fn handle_pty_peer_close(
    _args: (),
    _ctx: &mut HandlerCtx<'_>,
) -> Result<RlOut, HandlerError> {
    Ok(RlOut {
        detail: pty_peer_close()?,
    })
}

pub(crate) fn register_resource_lifetime_tests(reg: &mut Registry<'_>) {
    register_handler!(PIPE_PARENT_EXITS_FIRST, handle_pipe_parent_exits_first);
    register_handler!(PIPE_CHILD_EXITS_FIRST, handle_pipe_child_exits_first);
    register_handler!(
        PIDFD_SUBSCRIBER_EXITS_FIRST,
        handle_pidfd_subscriber_exits_first
    );
    register_handler!(PTY_PEER_CLOSE, handle_pty_peer_close);
    register_leaf_subcommand!("resource-lifetime-test", |args: &[String]| -> i32 {
        leaf_subcmd::run(args)
    });

    for &agent in RL_AGENTS {
        for &parent_bt in crate::BinaryType::ALL {
            for &child_bt in crate::BinaryType::ALL {
                register_pair_test(
                    reg,
                    agent,
                    parent_bt,
                    child_bt,
                    "parent_exits_first.pipe",
                    &PIPE_PARENT_EXITS_FIRST,
                );
                register_pair_test(
                    reg,
                    agent,
                    parent_bt,
                    child_bt,
                    "child_exits_first.pipe",
                    &PIPE_CHILD_EXITS_FIRST,
                );
                register_pair_test(
                    reg,
                    agent,
                    parent_bt,
                    child_bt,
                    "subscriber_exits_first.pidfd",
                    &PIDFD_SUBSCRIBER_EXITS_FIRST,
                );
            }
        }

        for &bt in crate::BinaryType::ALL {
            let bt_label = bt.label();
            let id = format!("RL.pty_peer_close.{bt_label}.{agent}");
            let agent_label = agent.to_string();
            reg.test("vscode", "resource_lifetime", id)
                .timeout(30)
                .build(move |cx| {
                    let leaf = cx.declare_ephemeral(
                        agent,
                        format!("RlPty_{}", bt.short_label()),
                        SpawnKind::Fork {
                            binary: fork_binary_label(bt),
                            inherit_listen_ports: vec![],
                        },
                    );
                    let agent_label = agent_label.clone();
                    Box::new(move |run| {
                        Box::pin(async move {
                            match run.run_leaf(&leaf, &PTY_PEER_CLOSE, ()).await {
                                Ok(out) if out.detail.contains("RL_PTY_PEER_CLOSE_OK") => {
                                    TestOutcome::new(&agent_label, true, out.detail)
                                }
                                Ok(out) => TestOutcome::new(&agent_label, false, out.detail),
                                Err(e) => {
                                    TestOutcome::new(&agent_label, false, format!("handler: {e}"))
                                }
                            }
                        })
                    })
                });
        }
    }
}

fn register_pair_test(
    reg: &mut Registry<'_>,
    agent: AgentName,
    parent_bt: crate::BinaryType,
    child_bt: crate::BinaryType,
    mode: &'static str,
    token: &'static HandlerToken<ChildBinaryArgs, RlOut>,
) {
    let parent_label = parent_bt.label();
    let child_label = child_bt.label();
    let id = format!("RL.{mode}.{parent_label}.{child_label}.{agent}");
    let agent_label = agent.to_string();
    reg.test("vscode", "resource_lifetime", id)
        .timeout(180)
        .build(move |cx| {
            let leaf = cx.declare_ephemeral(
                agent,
                format!(
                    "Rl_{}_{}_{}",
                    mode.replace(['.', '-'], "_"),
                    parent_bt.short_label(),
                    child_bt.short_label()
                ),
                SpawnKind::Fork {
                    binary: fork_binary_label(parent_bt),
                    inherit_listen_ports: vec![],
                },
            );
            let agent_label = agent_label.clone();
            Box::new(move |run| {
                Box::pin(async move {
                    let child_binary = crate::binary_path(child_bt, run.self_exe());
                    match run
                        .run_leaf_with_timeout(
                            &leaf,
                            token,
                            ChildBinaryArgs { child_binary },
                            Some(150),
                        )
                        .await
                    {
                        Ok(out) if out.detail.contains("_OK") => {
                            TestOutcome::new(&agent_label, true, out.detail)
                        }
                        Ok(out) => TestOutcome::new(&agent_label, false, out.detail),
                        Err(e) => TestOutcome::new(&agent_label, false, format!("handler: {e}")),
                    }
                })
            })
        });
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
}

fn close_fd(fd: i32) {
    // SAFETY: best-effort close of a raw fd owned by the current test path.
    unsafe {
        libc::close(fd);
    }
}

fn wait_status(pid: libc::pid_t) -> Result<i32, String> {
    let mut status = 0;
    // SAFETY: pid was returned by fork in the current process.
    let waited = unsafe { libc::waitpid(pid, std::ptr::from_mut(&mut status), 0) };
    if waited != pid {
        return Err(format!(
            "waitpid({pid}) returned {waited}: {}",
            std::io::Error::last_os_error()
        ));
    }
    if libc::WIFEXITED(status) {
        Ok(libc::WEXITSTATUS(status))
    } else if libc::WIFSIGNALED(status) {
        Ok(128 + libc::WTERMSIG(status))
    } else {
        Ok(99)
    }
}

fn do_execv(exe: &str, args: &[&str]) -> ! {
    let c_exe = std::ffi::CString::new(exe).unwrap();
    let c_args: Vec<std::ffi::CString> = args
        .iter()
        .map(|arg| std::ffi::CString::new(*arg).unwrap())
        .collect();
    let mut argv: Vec<*const libc::c_char> = Vec::with_capacity(c_args.len() + 2);
    argv.push(c_exe.as_ptr());
    for arg in &c_args {
        argv.push(arg.as_ptr());
    }
    argv.push(std::ptr::null());
    // SAFETY: c_exe and argv point to valid NUL-terminated strings and argv is NUL-terminated.
    unsafe {
        libc::execv(c_exe.as_ptr(), argv.as_ptr());
    }
    eprintln!(
        "resource-lifetime execv({exe}): {}",
        std::io::Error::last_os_error()
    );
    // SAFETY: terminate the child process after failed exec.
    unsafe {
        libc::_exit(127);
    }
}

fn read_until_eof(fd: i32, timeout_ms: i32) -> Result<(Vec<u8>, bool), String> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms as u64);
    let mut data = Vec::new();
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Ok((data, false));
        }
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
            revents: 0,
        };
        let poll_ms = remaining.as_millis().min(1000) as i32;
        // SAFETY: pfd points to one initialized pollfd entry.
        let ready = unsafe { libc::poll(std::ptr::from_mut(&mut pfd), 1, poll_ms) };
        if ready < 0 {
            if errno() == libc::EINTR {
                continue;
            }
            return Err(format!("poll fd {fd}: errno={}", errno()));
        }
        if ready == 0 {
            continue;
        }
        let mut buf = [0u8; 256];
        // SAFETY: buf is valid writable storage and fd is live.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
        if n > 0 {
            data.extend_from_slice(&buf[..n as usize]);
            continue;
        }
        if n == 0 {
            return Ok((data, true));
        }
        let err = errno();
        if err == libc::EINTR || err == libc::EAGAIN {
            continue;
        }
        return Err(format!("read fd {fd}: errno={err}"));
    }
}

fn pipe_child_exits_first(child_binary: &str) -> Result<String, HandlerError> {
    let mut pipe_fds = [0; 2];
    // SAFETY: pipe_fds has room for two fds.
    if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } != 0 {
        return Err(HandlerError(format!("pipe: errno={}", errno())));
    }

    // SAFETY: fork creates the child that immediately execs the requested harness binary.
    let child = unsafe { libc::fork() };
    if child < 0 {
        close_fd(pipe_fds[0]);
        close_fd(pipe_fds[1]);
        return Err(HandlerError(format!("fork child: errno={}", errno())));
    }
    if child == 0 {
        close_fd(pipe_fds[0]);
        let fd = pipe_fds[1].to_string();
        do_execv(
            child_binary,
            &["resource-lifetime-test", "pipe-write-exit", &fd],
        );
    }

    close_fd(pipe_fds[1]);
    let (data, eof) = read_until_eof(pipe_fds[0], 10_000).map_err(HandlerError)?;
    close_fd(pipe_fds[0]);
    let exit = wait_status(child).map_err(HandlerError)?;
    let text = String::from_utf8_lossy(&data);
    if text.as_bytes().contains_subslice(MARKER) && eof && exit == 0 {
        Ok(format!(
            "RL_CHILD_EXITS_FIRST_PIPE_OK:bytes={},exit={exit}",
            data.len()
        ))
    } else {
        Ok(format!(
            "RL_CHILD_EXITS_FIRST_PIPE_FAIL:data={text:?},eof={eof},exit={exit}"
        ))
    }
}

fn pipe_parent_exits_first(child_binary: &str) -> Result<String, HandlerError> {
    let mut pipe_fds = [0; 2];
    // SAFETY: pipe_fds has room for two fds.
    if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } != 0 {
        return Err(HandlerError(format!("pipe: errno={}", errno())));
    }

    // SAFETY: fork creates the short-lived parent process for this ordering probe.
    let parent = unsafe { libc::fork() };
    if parent < 0 {
        close_fd(pipe_fds[0]);
        close_fd(pipe_fds[1]);
        return Err(HandlerError(format!("fork parent: errno={}", errno())));
    }
    if parent == 0 {
        close_fd(pipe_fds[0]);
        // SAFETY: fork creates the child writer that outlives this short-lived parent.
        let child = unsafe { libc::fork() };
        if child < 0 {
            // SAFETY: child-side immediate exit on setup failure.
            unsafe { libc::_exit(11) };
        }
        if child == 0 {
            let fd = pipe_fds[1].to_string();
            do_execv(
                child_binary,
                &["resource-lifetime-test", "pipe-write-sleep", &fd, "150"],
            );
        }
        close_fd(pipe_fds[1]);
        // SAFETY: parent-exits-first is the scenario under test.
        unsafe { libc::_exit(0) };
    }

    close_fd(pipe_fds[1]);
    let parent_exit = wait_status(parent).map_err(HandlerError)?;
    let (data, eof) = read_until_eof(pipe_fds[0], 10_000).map_err(HandlerError)?;
    close_fd(pipe_fds[0]);
    let text = String::from_utf8_lossy(&data);
    if text.as_bytes().contains_subslice(MARKER) && eof && parent_exit == 0 {
        Ok(format!(
            "RL_PARENT_EXITS_FIRST_PIPE_OK:bytes={},parent_exit={parent_exit}",
            data.len()
        ))
    } else {
        Ok(format!(
            "RL_PARENT_EXITS_FIRST_PIPE_FAIL:data={text:?},eof={eof},parent_exit={parent_exit}"
        ))
    }
}

fn pidfd_subscriber_exits_first(child_binary: &str) -> Result<String, HandlerError> {
    let mut verdict_pipe = [0; 2];
    // SAFETY: verdict_pipe has room for two fds.
    if unsafe { libc::pipe(verdict_pipe.as_mut_ptr()) } != 0 {
        return Err(HandlerError(format!("verdict pipe: errno={}", errno())));
    }

    // SAFETY: fork creates the pidfd target process.
    let target = unsafe { libc::fork() };
    if target < 0 {
        close_fd(verdict_pipe[0]);
        close_fd(verdict_pipe[1]);
        return Err(HandlerError(format!("fork target: errno={}", errno())));
    }
    if target == 0 {
        close_fd(verdict_pipe[0]);
        close_fd(verdict_pipe[1]);
        do_execv(
            child_binary,
            &["resource-lifetime-test", "sleep-exit", "350", "17"],
        );
    }

    // SAFETY: fork creates the subscriber that opens the pidfd, then exits before the target.
    let subscriber = unsafe { libc::fork() };
    if subscriber < 0 {
        close_fd(verdict_pipe[0]);
        close_fd(verdict_pipe[1]);
        // SAFETY: clean up the known target process on setup failure.
        unsafe { libc::kill(target, libc::SIGKILL) };
        let _ = wait_status(target);
        return Err(HandlerError(format!("fork subscriber: errno={}", errno())));
    }
    if subscriber == 0 {
        close_fd(verdict_pipe[0]);
        let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, target as libc::pid_t, 0) } as i32;
        if pidfd < 0 {
            let msg = format!("PIDFD_OPEN_FAIL:{}", errno());
            write_all_raw(verdict_pipe[1], msg.as_bytes());
            close_fd(verdict_pipe[1]);
            // SAFETY: child-side immediate exit after reporting failure.
            unsafe { libc::_exit(12) };
        }
        // SAFETY: fcntl adjusts the close-on-exec flag on a live fd.
        if unsafe { libc::fcntl(pidfd, libc::F_SETFD, 0) } != 0 {
            let msg = format!("PIDFD_FCNTL_FAIL:{}", errno());
            write_all_raw(verdict_pipe[1], msg.as_bytes());
            close_fd(pidfd);
            close_fd(verdict_pipe[1]);
            // SAFETY: child-side immediate exit after reporting failure.
            unsafe { libc::_exit(13) };
        }
        // SAFETY: fork creates the inherited-pidfd poller.
        let poller = unsafe { libc::fork() };
        if poller < 0 {
            let msg = format!("PIDFD_POLLER_FORK_FAIL:{}", errno());
            write_all_raw(verdict_pipe[1], msg.as_bytes());
            close_fd(pidfd);
            close_fd(verdict_pipe[1]);
            // SAFETY: child-side immediate exit after reporting failure.
            unsafe { libc::_exit(14) };
        }
        if poller == 0 {
            let pidfd_s = pidfd.to_string();
            let verdict_s = verdict_pipe[1].to_string();
            do_execv(
                child_binary,
                &[
                    "resource-lifetime-test",
                    "pidfd-poll-write",
                    &pidfd_s,
                    &verdict_s,
                    "5000",
                ],
            );
        }
        close_fd(pidfd);
        close_fd(verdict_pipe[1]);
        // SAFETY: subscriber exits before target while poller keeps the pidfd alive.
        unsafe { libc::_exit(0) };
    }

    close_fd(verdict_pipe[1]);
    let subscriber_exit = wait_status(subscriber).map_err(HandlerError)?;
    let (verdict, eof) = read_until_eof(verdict_pipe[0], 10_000).map_err(HandlerError)?;
    close_fd(verdict_pipe[0]);
    let target_exit = wait_status(target).map_err(HandlerError)?;
    let verdict_text = String::from_utf8_lossy(&verdict);
    if verdict_text.contains("PIDFD_POLL_OK") && eof && subscriber_exit == 0 && target_exit == 17 {
        Ok(format!(
            "RL_SUBSCRIBER_EXITS_FIRST_PIDFD_OK:subscriber={subscriber_exit},target={target_exit}"
        ))
    } else {
        Ok(format!(
            "RL_SUBSCRIBER_EXITS_FIRST_PIDFD_FAIL:verdict={verdict_text:?},eof={eof},subscriber={subscriber_exit},target={target_exit}"
        ))
    }
}

fn pty_peer_close() -> Result<String, HandlerError> {
    // SAFETY: posix_openpt returns a fresh master fd on success.
    let master = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC) };
    if master < 0 {
        return Err(HandlerError(format!("posix_openpt: errno={}", errno())));
    }
    // SAFETY: grantpt/unlockpt operate on a live pty master fd.
    if unsafe { libc::grantpt(master) } != 0 || unsafe { libc::unlockpt(master) } != 0 {
        let err = errno();
        close_fd(master);
        return Err(HandlerError(format!("grantpt/unlockpt: errno={err}")));
    }
    let mut buf = vec![0i8; 128];
    // SAFETY: buf is writable storage for ptsname_r.
    let rc = unsafe { libc::ptsname_r(master, buf.as_mut_ptr(), buf.len()) };
    if rc != 0 {
        close_fd(master);
        return Err(HandlerError(format!("ptsname_r: errno={rc}")));
    }
    let nul = buf
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| HandlerError("ptsname_r returned unterminated path".into()))?;
    let path_bytes: Vec<u8> = buf[..nul].iter().map(|&b| b as u8).collect();
    let slave_path = std::ffi::CString::new(path_bytes).map_err(|e| HandlerError(e.to_string()))?;
    // SAFETY: slave_path is a valid nul-terminated pts path.
    let slave = unsafe { libc::open(slave_path.as_ptr(), libc::O_RDWR | libc::O_NOCTTY) };
    if slave < 0 {
        let err = errno();
        close_fd(master);
        return Err(HandlerError(format!("open slave: errno={err}")));
    }

    // SAFETY: fork creates a child that writes to the slave then exits.
    let child = unsafe { libc::fork() };
    if child < 0 {
        let err = errno();
        close_fd(master);
        close_fd(slave);
        return Err(HandlerError(format!("pty fork: errno={err}")));
    }
    if child == 0 {
        close_fd(master);
        let msg = b"RL_PTY_PEER_OK\n";
        write_all_raw(slave, msg);
        close_fd(slave);
        // SAFETY: child-side immediate exit after writing to the pty slave.
        unsafe { libc::_exit(0) };
    }

    close_fd(slave);
    let (data, peer_closed) = read_pty_until_peer_close(master, 10_000).map_err(HandlerError)?;
    close_fd(master);
    let child_exit = wait_status(child).map_err(HandlerError)?;
    let text = String::from_utf8_lossy(&data);
    if text == PTY_MARKER && peer_closed && child_exit == 0 {
        Ok(format!(
            "RL_PTY_PEER_CLOSE_OK:bytes={},child={child_exit}",
            data.len()
        ))
    } else {
        Ok(format!(
            "RL_PTY_PEER_CLOSE_FAIL:data={text:?},peer_closed={peer_closed},child={child_exit}"
        ))
    }
}

fn read_pty_until_peer_close(fd: i32, timeout_ms: i32) -> Result<(Vec<u8>, bool), String> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms as u64);
    let mut data = Vec::new();
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Ok((data, false));
        }
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
            revents: 0,
        };
        // SAFETY: pfd points to one initialized pollfd entry.
        let ready = unsafe {
            libc::poll(
                std::ptr::from_mut(&mut pfd),
                1,
                remaining.as_millis().min(1000) as i32,
            )
        };
        if ready < 0 {
            if errno() == libc::EINTR {
                continue;
            }
            return Err(format!("pty poll: errno={}", errno()));
        }
        if ready == 0 {
            continue;
        }
        let mut chunk = [0u8; 256];
        // SAFETY: chunk is valid writable storage and fd is live.
        let n = unsafe { libc::read(fd, chunk.as_mut_ptr().cast::<libc::c_void>(), chunk.len()) };
        if n > 0 {
            data.extend_from_slice(&chunk[..n as usize]);
            continue;
        }
        if n == 0 {
            return Ok((data, true));
        }
        let err = errno();
        if err == libc::EINTR || err == libc::EAGAIN {
            continue;
        }
        if err == libc::EIO {
            return Ok((data, true));
        }
        return Err(format!("pty read: errno={err}"));
    }
}

fn write_all_raw(fd: i32, mut data: &[u8]) -> bool {
    while !data.is_empty() {
        // SAFETY: data is readable and fd is expected to be a live descriptor.
        let n = unsafe { libc::write(fd, data.as_ptr().cast::<libc::c_void>(), data.len()) };
        if n < 0 {
            if errno() == libc::EINTR {
                continue;
            }
            return false;
        }
        data = &data[n as usize..];
    }
    true
}

trait ContainsSubslice {
    fn contains_subslice(&self, needle: &[u8]) -> bool;
}

impl ContainsSubslice for [u8] {
    fn contains_subslice(&self, needle: &[u8]) -> bool {
        self.windows(needle.len()).any(|window| window == needle)
    }
}

mod leaf_subcmd {
    pub(super) fn run(args: &[String]) -> i32 {
        match args.get(2).map(String::as_str) {
            Some("pipe-write-exit") => pipe_write(args, 0),
            Some("pipe-write-sleep") => {
                let delay = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(100);
                pipe_write(args, delay)
            }
            Some("sleep-exit") => sleep_exit(args),
            Some("pidfd-poll-write") => pidfd_poll_write(args),
            other => {
                eprintln!("resource-lifetime-test: unknown subcommand: {other:?}");
                2
            }
        }
    }

    fn pipe_write(args: &[String], delay_ms: u64) -> i32 {
        let fd: i32 = match args.get(3).and_then(|s| s.parse().ok()) {
            Some(fd) => fd,
            None => return 2,
        };
        if delay_ms != 0 {
            std::thread::sleep(std::time::Duration::from_millis(delay_ms));
        }
        let ok = super::write_all_raw(fd, super::MARKER) && super::write_all_raw(fd, b"\n");
        super::close_fd(fd);
        if ok { 0 } else { 1 }
    }

    fn sleep_exit(args: &[String]) -> i32 {
        let delay_ms = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(250);
        let code = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(0);
        std::thread::sleep(std::time::Duration::from_millis(delay_ms));
        code
    }

    fn pidfd_poll_write(args: &[String]) -> i32 {
        let pidfd: i32 = match args.get(3).and_then(|s| s.parse().ok()) {
            Some(fd) => fd,
            None => return 2,
        };
        let verdict_fd: i32 = match args.get(4).and_then(|s| s.parse().ok()) {
            Some(fd) => fd,
            None => return 2,
        };
        let timeout_ms: i32 = args.get(5).and_then(|s| s.parse().ok()).unwrap_or(5000);
        let mut pfd = libc::pollfd {
            fd: pidfd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: pfd points to one initialized pollfd entry for the inherited pidfd.
        let rc = unsafe { libc::poll(std::ptr::from_mut(&mut pfd), 1, timeout_ms) };
        let verdict = if rc > 0 && (pfd.revents & libc::POLLIN) != 0 {
            "PIDFD_POLL_OK"
        } else if rc == 0 {
            "PIDFD_POLL_TIMEOUT"
        } else if rc < 0 {
            "PIDFD_POLL_ERR"
        } else {
            "PIDFD_POLL_NO_POLLIN"
        };
        let _ = super::write_all_raw(verdict_fd, verdict.as_bytes());
        super::close_fd(pidfd);
        super::close_fd(verdict_fd);
        if verdict == "PIDFD_POLL_OK" { 0 } else { 1 }
    }
}
