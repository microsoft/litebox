// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Agent command executor. Reads commands from stdin, executes them,
//! writes responses to stdout. Intermediate nodes forward commands to
//! their children.

use crate::protocol::{Command, Response};
use std::collections::HashMap;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::os::unix::net::UnixListener as StdUnixListener;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWriteExt, BufReader};
use tokio::time::Duration;

struct ChildHandle {
    stdin: tokio::process::ChildStdin,
    stdout: BufReader<tokio::process::ChildStdout>,
    #[allow(dead_code)]
    process: tokio::process::Child,
}

struct ListenerEntry {
    fd: OwnedFd,
    #[allow(dead_code)]
    task: tokio::task::JoinHandle<()>,
    #[allow(dead_code)]
    accepted: Arc<AtomicUsize>,
}

enum BackgroundProcess {
    Tokio {
        process: tokio::process::Child,
        #[allow(dead_code)] // ready-marker scanners write here; no consumer remains
        stdout: Arc<Mutex<Vec<u8>>>,
        #[allow(dead_code)] // ready-marker scanners write here; no consumer remains
        stderr: Arc<Mutex<Vec<u8>>>,
        drains: Vec<tokio::task::JoinHandle<()>>,
    },
}

fn marker_stream_matches(configured: &str, actual: &str) -> bool {
    matches!(configured, "either") || configured == actual
}

fn spawn_output_capture<R>(
    reader: R,
    actual_stream: &'static str,
    marker_stream: String,
    ready_marker: String,
    ready_seen: Arc<AtomicBool>,
    buffer: Arc<Mutex<Vec<u8>>>,
) -> tokio::task::JoinHandle<()>
where
    R: AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut reader = BufReader::new(reader);
        let mut line = Vec::new();
        loop {
            line.clear();
            match reader.read_until(b'\n', &mut line).await {
                Ok(0) => break,
                Ok(_) => {
                    buffer
                        .lock()
                        .expect("output buffer mutex")
                        .extend_from_slice(&line);
                    if marker_stream_matches(&marker_stream, actual_stream) {
                        let text = String::from_utf8_lossy(&line);
                        if text.contains(&ready_marker) {
                            ready_seen.store(true, Ordering::SeqCst);
                        }
                    }
                }
                Err(_) => break,
            }
        }
    })
}

const INHERITED_LISTEN_FDS_ENV: &str = "LITEBOX_TEST_HARNESS_INHERITED_LISTEN_FDS";
const INHERITED_LISTEN_FD_BASE: i32 = 80;
const INHERITED_LISTEN_FD_LIMIT: i32 = 99;

/// All per-agent mutable state, lifted from `agent_loop`'s locals.
///
/// Phase 0 of the handler refactor: this struct exists so subsequent
/// phases can move per-family match arms into family files that take
/// `&mut AgentState`. As families migrate to straight-line handlers,
/// the per-family handle tables (e.g. `inotifies`, `next_inotify_id`)
/// will be deleted from this struct — handlers will hold those
/// resources in their own stack frames.
///
/// Terminal shape after Phase 2 is just `{ self_exe, children }`;
/// during migration the struct shrinks one field-pair per family.
pub(crate) struct AgentState {
    children: HashMap<String, ChildHandle>,
    listeners: HashMap<u16, Vec<ListenerEntry>>,
    unix_listeners: HashMap<String, tokio::task::JoinHandle<()>>,
    unix_pair_listeners: HashMap<String, StdUnixListener>,
    unix_pairs: HashMap<u64, OwnedFd>,
    background_pids: HashMap<u32, BackgroundProcess>,
}

impl AgentState {
    fn new(listeners: HashMap<u16, Vec<ListenerEntry>>) -> Self {
        Self {
            children: HashMap::new(),
            listeners,
            unix_listeners: HashMap::new(),
            unix_pair_listeners: HashMap::new(),
            unix_pairs: HashMap::new(),
            background_pids: HashMap::new(),
        }
    }
}

/// Run the agent. Reads commands from stdin, executes, responds on stdout.
pub fn run(self_exe: &str) {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(agent_loop(self_exe));
}

#[allow(clippy::too_many_lines)] // exhaustive runner / dispatch table
//
// The match-arm dispatch below is **closed to test-specific additions**.
// New test behavior is expressed as a registered handler (see
// `crate::handlers` + `register_handler!`), invoked through
// `Command::Run { handler, args }` and `dispatch_run` below. The
// remaining `Command::*` arms are generic primitives (process
// lifecycle, fs / net / unix / eventfd I/O) shared across many
// handlers. If you are about to add a new arm here for a single test
// family, write a handler in `coordinator/<family>.rs` instead. See
// `litebox_test_harness/CLAUDE.md` "Handler Model" for the pattern.
async fn agent_loop(self_exe: &str) {
    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin);
    let imported_listeners = match import_inherited_listeners() {
        Ok(listeners) => listeners,
        Err(error) => {
            eprintln!("[agent] failed to import inherited listen fds: {error}");
            HashMap::new()
        }
    };
    let mut state = AgentState::new(imported_listeners);
    // Destructure-bind every field as a local `&mut` reference so the
    // existing match arms can keep their syntax (`inotifies.insert(...)`
    // rather than `state.inotifies.insert(...)`). Phase 2 family
    // migrations will replace these bindings with `&mut AgentState`
    // passed to family-local dispatch functions.
    let AgentState {
        children,
        listeners,
        unix_listeners,
        unix_pair_listeners,
        unix_pairs,
        background_pids,
    } = &mut state;

    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) | Err(_) => break, // EOF or error
            Ok(_) => {}
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let cmd: Command = match serde_json::from_str(trimmed) {
            Ok(c) => c,
            Err(e) => {
                respond(&Response::Error {
                    error: format!("parse error: {e}"),
                })
                .await;
                continue;
            }
        };

        match cmd {
            Command::Spawn { children: names } => {
                for name in &names {
                    match spawn_child(self_exe, name) {
                        Ok(handle) => {
                            children.insert(name.clone(), handle);
                        }
                        Err(e) => {
                            respond(&Response::Error {
                                error: format!("spawn {name}: {e}"),
                            })
                            .await;
                        }
                    }
                }
                respond(&Response::Ok {
                    data: Some(format!("{} children spawned", names.len())),
                })
                .await;
            }

            Command::SpawnRemote { children: names } => {
                // Use the non-PIE binary to force remote worker migration.
                // Required dependency: panic if missing rather than
                // returning Response::Error — the registration system
                // ensures only tests that declared a NonPie ephemeral
                // reach this command, so a missing binary at this
                // point indicates a setup error that should surface
                // loudly.
                let remote_exe = litebox_test_harness::nonpie_binary();
                for name in &names {
                    match spawn_child(&remote_exe, name) {
                        Ok(handle) => {
                            children.insert(name.clone(), handle);
                        }
                        Err(e) => {
                            respond(&Response::Error {
                                error: format!("spawn_remote {name}: {e}"),
                            })
                            .await;
                        }
                    }
                }
                respond(&Response::Ok {
                    data: Some(format!("{} remote children spawned", names.len())),
                })
                .await;
            }

            Command::Fork {
                name,
                binary,
                inherit_listen_ports,
            } => {
                let exe = match binary.as_str() {
                    // Required dependency; panic for clarity (see SpawnRemote handler).
                    "nonpie" => litebox_test_harness::nonpie_binary(),
                    "static-pie-glibc" => litebox_test_harness::static_pie_glibc_binary(),
                    "static-pie-musl" => litebox_test_harness::static_pie_musl_binary(),
                    "non-pie-static-musl" => litebox_test_harness::non_pie_static_musl_binary(),
                    _ => self_exe.to_string(), // "self" or default
                };

                let inherited = match prepare_inherited_listeners(&listeners, &inherit_listen_ports)
                {
                    Ok(inherited) => inherited,
                    Err(error) => {
                        respond(&Response::Error {
                            error: format!("fork {name}: {error}"),
                        })
                        .await;
                        continue;
                    }
                };

                match spawn_child_with_inherited(&exe, &name, &inherited) {
                    Ok(handle) => {
                        children.insert(name.clone(), handle);
                        respond(&Response::Ok {
                            data: Some(format!("forked {name} (binary={binary})")),
                        })
                        .await;
                    }
                    Err(e) => {
                        respond(&Response::Error {
                            error: format!("fork {name}: {e}"),
                        })
                        .await;
                    }
                }
            }

            Command::Forward { target, inner } => {
                if let Some(child) = children.get_mut(&target) {
                    let resp = send_to_child(child, &inner).await;
                    respond(&resp).await;
                } else {
                    respond(&Response::Error {
                        error: format!("unknown child: {target}"),
                    })
                    .await;
                }
            }

            Command::Run {
                handler,
                args,
                timeout_secs: _,
            } => {
                let resp = litebox_test_harness::handlers::dispatch_run(
                    &handler,
                    args,
                    self_exe,
                    &mut reader,
                )
                .await;
                respond(&resp).await;
            }

            Command::Resume { tag } => {
                respond(&Response::Error {
                    error: format!("Resume {{ tag: {tag} }} received outside handler context"),
                })
                .await;
            }

            Command::Exec {
                args,
                timeout_secs,
                stdin: stdin_content,
                background,
                env,
            } => {
                if args.is_empty() {
                    respond(&Response::Error {
                        error: "exec requires args".to_string(),
                    })
                    .await;
                    continue;
                }

                let use_piped_stdin = stdin_content.is_some();
                let mut cmd = tokio::process::Command::new(&args[0]);
                cmd.args(&args[1..]);
                for (key, value) in &env {
                    cmd.env(key, value);
                }
                if use_piped_stdin {
                    cmd.stdin(std::process::Stdio::piped());
                } else {
                    cmd.stdin(std::process::Stdio::null());
                }

                if background {
                    cmd.stdout(std::process::Stdio::null());
                    cmd.stderr(std::process::Stdio::null());
                    match cmd.spawn() {
                        Ok(mut child) => {
                            // Write stdin content if provided.
                            if let Some(content) = stdin_content
                                && let Some(mut child_stdin) = child.stdin.take()
                            {
                                use tokio::io::AsyncWriteExt;
                                let _ = child_stdin.write_all(content.as_bytes()).await;
                                // drop closes the pipe
                            }
                            let pid = child.id().unwrap_or(0);
                            background_pids.insert(
                                pid,
                                BackgroundProcess::Tokio {
                                    process: child,
                                    stdout: Arc::new(Mutex::new(Vec::new())),
                                    stderr: Arc::new(Mutex::new(Vec::new())),
                                    drains: Vec::new(),
                                },
                            );
                            respond(&Response::Background { pid }).await;
                        }
                        Err(e) => {
                            respond(&Response::Error {
                                error: format!("exec spawn: {e}"),
                            })
                            .await;
                        }
                    }
                } else {
                    cmd.stdout(std::process::Stdio::piped());
                    cmd.stderr(std::process::Stdio::piped());
                    let timeout = Duration::from_secs(timeout_secs.unwrap_or(10));
                    let mut child = match cmd.spawn() {
                        Ok(c) => c,
                        Err(e) => {
                            respond(&Response::Error {
                                error: format!("exec spawn: {e}"),
                            })
                            .await;
                            continue;
                        }
                    };

                    // Write stdin content if provided.
                    if let Some(content) = stdin_content
                        && let Some(mut child_stdin) = child.stdin.take()
                    {
                        use tokio::io::AsyncWriteExt;
                        let _ = child_stdin.write_all(content.as_bytes()).await;
                        // drop closes the pipe
                    }

                    let mut child_stdout = child.stdout.take().unwrap();
                    let mut child_stderr = child.stderr.take().unwrap();

                    // Collect stdout/stderr and wait, with timeout for deadlock detection.
                    let result = tokio::time::timeout(timeout, async {
                        let mut out = Vec::new();
                        let mut err = Vec::new();
                        let (r1, r2, status) = tokio::join!(
                            tokio::io::AsyncReadExt::read_to_end(&mut child_stdout, &mut out),
                            tokio::io::AsyncReadExt::read_to_end(&mut child_stderr, &mut err),
                            child.wait(),
                        );
                        let _ = r1;
                        let _ = r2;
                        (out, err, status)
                    })
                    .await;

                    match result {
                        Ok((out, err, Ok(status))) => {
                            respond(&Response::ExecResult {
                                exit_code: status.code().unwrap_or(-1),
                                stdout: String::from_utf8_lossy(&out).to_string(),
                                stderr: String::from_utf8_lossy(&err).to_string(),
                            })
                            .await;
                        }
                        Ok((_, _, Err(e))) => {
                            respond(&Response::Error {
                                error: format!("exec wait: {e}"),
                            })
                            .await;
                        }
                        Err(_) => {
                            // Timed out — send SIGKILL but don't await (wait can
                            // hang in litebox due to process reaping bug).
                            let _ = child.start_kill();
                            respond(&Response::ExecTimeout {
                                stderr: format!(
                                    "process timed out after {}s (likely deadlocked)",
                                    timeout.as_secs()
                                ),
                            })
                            .await;
                        }
                    }
                }
            }

            Command::ExecReady {
                args,
                ready_marker,
                timeout_secs,
                stdin: stdin_content,
                stream,
            } => {
                if args.is_empty() {
                    respond(&Response::Error {
                        error: "exec_ready requires args".to_string(),
                    })
                    .await;
                    continue;
                }
                if !matches!(stream.as_str(), "stdout" | "stderr" | "either") {
                    respond(&Response::Error {
                        error: format!(
                            "invalid marker stream {stream:?}; expected stdout, stderr, or either"
                        ),
                    })
                    .await;
                    continue;
                }

                let mut cmd = tokio::process::Command::new(&args[0]);
                cmd.args(&args[1..]);
                if stdin_content.is_some() {
                    cmd.stdin(std::process::Stdio::piped());
                } else {
                    cmd.stdin(std::process::Stdio::null());
                }
                cmd.stdout(std::process::Stdio::piped());
                cmd.stderr(std::process::Stdio::piped());

                let mut child = match cmd.spawn() {
                    Ok(c) => c,
                    Err(e) => {
                        respond(&Response::Error {
                            error: format!("exec_ready spawn: {e}"),
                        })
                        .await;
                        continue;
                    }
                };

                if let Some(content) = stdin_content
                    && let Some(mut child_stdin) = child.stdin.take()
                {
                    let _ = child_stdin.write_all(content.as_bytes()).await;
                    let _ = child_stdin.flush().await;
                    drop(child_stdin);
                }

                let Some(stdout) = child.stdout.take() else {
                    respond(&Response::Error {
                        error: "exec_ready: stdout pipe missing".to_string(),
                    })
                    .await;
                    continue;
                };
                let Some(stderr) = child.stderr.take() else {
                    respond(&Response::Error {
                        error: "exec_ready: stderr pipe missing".to_string(),
                    })
                    .await;
                    continue;
                };

                let stdout_buf = Arc::new(Mutex::new(Vec::new()));
                let stderr_buf = Arc::new(Mutex::new(Vec::new()));
                let ready_seen = Arc::new(AtomicBool::new(false));
                let stdout_task = spawn_output_capture(
                    stdout,
                    "stdout",
                    stream.clone(),
                    ready_marker.clone(),
                    Arc::clone(&ready_seen),
                    Arc::clone(&stdout_buf),
                );
                let stderr_task = spawn_output_capture(
                    stderr,
                    "stderr",
                    stream,
                    ready_marker,
                    Arc::clone(&ready_seen),
                    Arc::clone(&stderr_buf),
                );

                let timeout = Duration::from_secs(timeout_secs.unwrap_or(30));
                let ready = tokio::time::timeout(timeout, async {
                    loop {
                        if ready_seen.load(Ordering::SeqCst) {
                            break Ok(());
                        }
                        match child.try_wait() {
                            Ok(Some(status)) => {
                                if ready_seen.load(Ordering::SeqCst) {
                                    break Ok(());
                                }
                                break Err(format!(
                                    "process exited before ready_marker (status={status})"
                                ));
                            }
                            Ok(None) => {}
                            Err(e) => break Err(format!("exec_ready poll: {e}")),
                        }
                        tokio::time::sleep(Duration::from_millis(25)).await;
                    }
                })
                .await;

                match ready {
                    Ok(Ok(())) => {
                        let pid = child.id().unwrap_or(0);
                        background_pids.insert(
                            pid,
                            BackgroundProcess::Tokio {
                                process: child,
                                stdout: stdout_buf,
                                stderr: stderr_buf,
                                drains: vec![stdout_task, stderr_task],
                            },
                        );
                        respond(&Response::BackgroundReady { pid }).await;
                    }
                    Ok(Err(error)) => {
                        let _ = child.start_kill();
                        stdout_task.abort();
                        stderr_task.abort();
                        respond(&Response::Error { error }).await;
                    }
                    Err(_) => {
                        let _ = child.start_kill();
                        stdout_task.abort();
                        stderr_task.abort();
                        respond(&Response::Error {
                            error: format!(
                                "ready_marker not observed within {}s",
                                timeout.as_secs()
                            ),
                        })
                        .await;
                    }
                }
            }

            Command::Exit => {
                // Abort all TCP echo servers.
                for (_, entries) in listeners.drain() {
                    for entry in entries {
                        entry.task.abort();
                    }
                }
                // Abort all Unix echo servers.
                for (_, task) in unix_listeners.drain() {
                    task.abort();
                }
                unix_pair_listeners.clear();
                unix_pairs.clear();
                // Terminate background processes.
                for (_, child) in background_pids.drain() {
                    terminate_background(child);
                }
                // Send exit to all children.
                for (_, mut child) in children.drain() {
                    let exit = Command::Exit;
                    let _ = send_to_child(&mut child, &exit).await;
                }
                break;
            }
        }
    }
}

async fn respond(resp: &Response) {
    let json = serde_json::to_string(resp).unwrap();
    let mut stdout = tokio::io::stdout();
    let _ = stdout.write_all(format!("{json}\n").as_bytes()).await;
    let _ = stdout.flush().await;
}

fn terminate_background(child: BackgroundProcess) {
    match child {
        BackgroundProcess::Tokio {
            mut process,
            drains,
            ..
        } => {
            let _ = process.start_kill();
            for drain in drains {
                drain.abort();
            }
        }
    }
}

fn import_inherited_listeners() -> Result<HashMap<u16, Vec<ListenerEntry>>, String> {
    let spec = match std::env::var(INHERITED_LISTEN_FDS_ENV) {
        Ok(spec) if !spec.is_empty() => spec,
        _ => return Ok(HashMap::new()),
    };
    let mut listeners = HashMap::new();
    let mut handler_env = Vec::new();
    for item in spec.split(',') {
        let (port_s, fd_s) = item
            .split_once('=')
            .ok_or_else(|| format!("bad inherited listener item {item:?}"))?;
        let port = port_s
            .parse::<u16>()
            .map_err(|e| format!("bad inherited port {port_s:?}: {e}"))?;
        let fd = fd_s
            .parse::<i32>()
            .map_err(|e| format!("bad inherited fd {fd_s:?}: {e}"))?;
        // SAFETY: The parent side passes each fd number exactly once via the
        // inheritance env var after dup'ing it into the reserved child slot.
        // This child process owns that descriptor after exec.
        let inherited_listener = unsafe { std::net::TcpListener::from_raw_fd(fd) };
        inherited_listener
            .set_nonblocking(true)
            .map_err(|e| format!("set inherited nonblocking fd {fd}: {e}"))?;
        let registry_fd = dup_fd_cloexec(inherited_listener.as_raw_fd())?;
        let handler_fd = dup_fd_cloexec(inherited_listener.as_raw_fd())?;
        handler_env.push(format!("{port}={}", handler_fd.into_raw_fd()));
        drop(inherited_listener);
        let task = tokio::spawn(async {});
        listeners
            .entry(port)
            .or_insert_with(Vec::new)
            .push(ListenerEntry {
                fd: registry_fd,
                task,
                accepted: Arc::new(AtomicUsize::new(0)),
            });
    }
    if !handler_env.is_empty() {
        // SAFETY: agent startup is single-threaded here; no other Rust threads are
        // concurrently reading or mutating the process environment.
        unsafe {
            std::env::set_var(INHERITED_LISTEN_FDS_ENV, handler_env.join(","));
        }
    }
    Ok(listeners)
}

fn prepare_inherited_listeners(
    listeners: &HashMap<u16, Vec<ListenerEntry>>,
    ports: &[u16],
) -> Result<Vec<(u16, OwnedFd)>, String> {
    if ports.len() > (INHERITED_LISTEN_FD_LIMIT - INHERITED_LISTEN_FD_BASE + 1) as usize {
        return Err(format!(
            "too many inherited listen ports: {} (slot range {INHERITED_LISTEN_FD_BASE}-{INHERITED_LISTEN_FD_LIMIT})",
            ports.len()
        ));
    }
    let mut inherited = Vec::with_capacity(ports.len());
    let bridge = litebox_test_harness::inherit_bridge()
        .lock()
        .expect("inherit bridge mutex");
    for (index, port) in ports.iter().copied().enumerate() {
        let raw_fd = if let Some(entry) = listeners.get(&port).and_then(|e| e.first()) {
            entry.fd.as_raw_fd()
        } else if let Some(owned) = bridge.get(&port) {
            owned.as_raw_fd()
        } else {
            return Err(format!("no listener registered for port {port}"));
        };
        let slot = INHERITED_LISTEN_FD_BASE + index as i32;
        inherited.push((port, dup_fd_to_inherited_slot(raw_fd, slot)?));
    }
    Ok(inherited)
}

fn dup_fd_cloexec(fd: i32) -> Result<OwnedFd, String> {
    // SAFETY: fcntl with F_DUPFD_CLOEXEC duplicates a valid fd owned by this
    // process and returns a fresh descriptor on success.
    let dup = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
    if dup < 0 {
        return Err(format!("dup fd {fd}: {}", std::io::Error::last_os_error()));
    }
    // SAFETY: `dup` is a newly returned fd and ownership is transferred to
    // OwnedFd so it will be closed exactly once.
    Ok(unsafe { OwnedFd::from_raw_fd(dup) })
}

fn dup_fd_to_inherited_slot(fd: i32, slot: i32) -> Result<OwnedFd, String> {
    // Inherited listen sockets use fd 80..99 in the child agent. This is above
    // stdio and normal low-number scratch fds, but below Litebox's documented
    // bridge/infrastructure bands: 100..199 parent bridge, 200..499 child
    // bridge host fds, and 500+ infrastructure fds. The mapping is passed as
    // `port=fd` in LITEBOX_TEST_HARNESS_INHERITED_LISTEN_FDS.
    // SAFETY: fcntl(F_GETFD) only inspects the candidate slot in this process.
    let flags = unsafe { libc::fcntl(slot, libc::F_GETFD) };
    if flags >= 0 {
        return Err(format!("inherited fd slot {slot} is already occupied"));
    }
    let err = std::io::Error::last_os_error();
    if err.raw_os_error() != Some(libc::EBADF) {
        return Err(format!("inspect inherited fd slot {slot}: {err}"));
    }
    // SAFETY: `fd` is a live listener duplicate from the registry, and `slot`
    // was just verified unused. F_DUPFD creates an inheritable duplicate at the
    // lowest free fd >= slot; because `slot` is free, success must return it.
    let ret = unsafe { libc::fcntl(fd, libc::F_DUPFD, slot) };
    if ret < 0 {
        return Err(format!(
            "dup fd {fd} to inherited slot {slot}: {}",
            std::io::Error::last_os_error()
        ));
    }
    if ret != slot {
        // SAFETY: ret is a fresh duplicate from fcntl and is not used further.
        let _ = unsafe { libc::close(ret) };
        return Err(format!(
            "inherited fd slot {slot} was not allocated (got {ret})"
        ));
    }
    // SAFETY: `slot` is now a freshly duplicated fd owned by this process. The
    // parent keeps it only until Command::spawn returns; dropping the OwnedFd
    // closes the parent's duplicate while the exec'd child keeps its copy.
    Ok(unsafe { OwnedFd::from_raw_fd(slot) })
}

fn spawn_child(self_exe: &str, id: &str) -> Result<ChildHandle, String> {
    spawn_child_with_inherited(self_exe, id, &[])
}

fn spawn_child_with_inherited(
    self_exe: &str,
    _id: &str,
    inherited: &[(u16, OwnedFd)],
) -> Result<ChildHandle, String> {
    let inherited_spec = inherited
        .iter()
        .map(|(port, fd)| format!("{port}={}", fd.as_raw_fd()))
        .collect::<Vec<_>>()
        .join(",");
    let mut command = tokio::process::Command::new(self_exe);
    command
        .arg("agent")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .env_remove(INHERITED_LISTEN_FDS_ENV);
    if !inherited_spec.is_empty() {
        command.env(INHERITED_LISTEN_FDS_ENV, inherited_spec);
    }
    let mut child = command.spawn().map_err(|e| format!("{e}"))?;

    let stdin = child.stdin.take().ok_or("no stdin")?;
    let stdout = child.stdout.take().ok_or("no stdout")?;

    Ok(ChildHandle {
        stdin,
        stdout: BufReader::new(stdout),
        process: child,
    })
}

/// Send a command to a child and read its response.
async fn send_to_child(child: &mut ChildHandle, cmd: &Command) -> Response {
    let json = serde_json::to_string(cmd).unwrap();
    if child
        .stdin
        .write_all(format!("{json}\n").as_bytes())
        .await
        .is_err()
    {
        return Response::Error {
            error: "write to child failed".to_string(),
        };
    }
    let _ = child.stdin.flush().await;

    let response_timeout = {
        let mut current = cmd;
        loop {
            match current {
                Command::Forward { inner, .. } => current = inner,
                Command::Exec {
                    timeout_secs: Some(timeout),
                    ..
                }
                | Command::ExecReady {
                    timeout_secs: Some(timeout),
                    ..
                }
                | Command::Run {
                    timeout_secs: Some(timeout),
                    ..
                } => break Duration::from_secs(timeout + 5),
                Command::Spawn { .. } | Command::SpawnRemote { .. } => {
                    break Duration::from_secs(65);
                }
                _ => break Duration::from_secs(60),
            }
        }
    };

    let mut line = String::new();
    match tokio::time::timeout(response_timeout, child.stdout.read_line(&mut line)).await {
        Ok(Ok(n)) if n > 0 => match serde_json::from_str(line.trim()) {
            Ok(resp) => resp,
            Err(e) => Response::Error {
                error: format!("child response parse: {e}: {line}"),
            },
        },
        Ok(Ok(_)) => Response::Error {
            error: "child EOF".to_string(),
        },
        Ok(Err(e)) => Response::Error {
            error: format!("child read: {e}"),
        },
        Err(_) => Response::Error {
            error: "child response timeout".to_string(),
        },
    }
}
