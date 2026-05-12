// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Agent command executor. Reads commands from stdin, executes them,
//! writes responses to stdout. Intermediate nodes forward commands to
//! their children.

use crate::protocol::{Command, FdRef, Response, SockOpt, SockOptValue, WaitPredicate};
use std::collections::HashMap;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::os::unix::net::{UnixListener as StdUnixListener, UnixStream as StdUnixStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::Duration;

struct ChildHandle {
    stdin: tokio::process::ChildStdin,
    stdout: BufReader<tokio::process::ChildStdout>,
    #[allow(dead_code)]
    process: tokio::process::Child,
}

struct ListenerEntry {
    fd: OwnedFd,
    task: tokio::task::JoinHandle<()>,
    accepted: Arc<AtomicUsize>,
}

struct EventfdEntry {
    fd: OwnedFd,
    #[allow(dead_code)] // Was read by eventfd_epollet_probe (now migrated).
    flags: String,
    authorized_readers: Vec<String>,
}

enum BackgroundProcess {
    Tokio {
        process: tokio::process::Child,
        stdout: Arc<Mutex<Vec<u8>>>,
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

type TcpConn = Arc<tokio::sync::Mutex<TcpStream>>;

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
    next_unix_pair_id: u64,
    connections: HashMap<u64, TcpConn>,
    next_conn_id: u64,
    eventfds: HashMap<u64, EventfdEntry>,
    next_eventfd_id: u64,
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
            next_unix_pair_id: 1,
            connections: HashMap::new(),
            next_conn_id: 1,
            eventfds: HashMap::new(),
            next_eventfd_id: 1,
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
        next_unix_pair_id,
        connections,
        next_conn_id,
        eventfds,
        next_eventfd_id,
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

            Command::FsRead { path } => match tokio::fs::read_to_string(&path).await {
                Ok(data) => respond(&Response::Ok { data: Some(data) }).await,
                Err(_) => respond(&Response::NotFound).await,
            },

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

            Command::GetPid => {
                let pid = std::process::id();
                respond(&Response::Ok {
                    data: Some(pid.to_string()),
                })
                .await;
            }

            Command::FsWrite { path, data } => {
                if let Some(parent) = std::path::Path::new(&path).parent() {
                    let _ = tokio::fs::create_dir_all(parent).await;
                }
                match tokio::fs::write(&path, &data).await {
                    Ok(()) => respond(&Response::Ok { data: None }).await,
                    Err(e) => {
                        respond(&Response::Error {
                            error: format!("write: {e}"),
                        })
                        .await;
                    }
                }
            }

            Command::FsDelete { path } => match tokio::fs::remove_file(&path).await {
                Ok(()) => respond(&Response::Ok { data: None }).await,
                Err(e) => {
                    respond(&Response::Error {
                        error: format!("delete: {e}"),
                    })
                    .await;
                }
            },

            Command::FsSymlink { target, link } => match tokio::fs::symlink(&target, &link).await {
                Ok(()) => respond(&Response::Ok { data: None }).await,
                Err(e) => {
                    respond(&Response::Error {
                        error: format!("symlink: {e}"),
                    })
                    .await;
                }
            },

            Command::FsReadlink { path } => match tokio::fs::read_link(&path).await {
                Ok(target) => {
                    respond(&Response::Ok {
                        data: Some(target.to_string_lossy().into_owned()),
                    })
                    .await;
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    respond(&Response::NotFound).await;
                }
                Err(e) => {
                    respond(&Response::Error {
                        error: format!("readlink: {e}"),
                    })
                    .await;
                }
            },

            Command::FsStat { path } => match tokio::fs::symlink_metadata(&path).await {
                Ok(meta) => {
                    let kind = if meta.is_symlink() {
                        "symlink"
                    } else if meta.is_dir() {
                        "dir"
                    } else {
                        "file"
                    };
                    respond(&Response::Ok {
                        data: Some(kind.to_string()),
                    })
                    .await;
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    respond(&Response::NotFound).await;
                }
                Err(e) => {
                    respond(&Response::Error {
                        error: format!("stat: {e}"),
                    })
                    .await;
                }
            },

            Command::NetListen {
                port,
                pre_bind_options,
            } => match create_listener_entry(port, &pre_bind_options) {
                Ok((actual_port, entry)) => {
                    listeners.entry(actual_port).or_default().push(entry);
                    respond(&Response::Listening { port: actual_port }).await;
                }
                Err(e) => {
                    respond(&Response::Error {
                        error: format!("bind {port}: {e}"),
                    })
                    .await;
                }
            },

            Command::NetListenerStats { port } => {
                if let Some(entries) = listeners.get(&port) {
                    let counts = entries
                        .iter()
                        .map(|entry| entry.accepted.load(Ordering::Relaxed) as u64)
                        .collect();
                    respond(&Response::ListenerStats { counts }).await;
                } else {
                    respond(&Response::Error {
                        error: format!("no listener registered for port {port}"),
                    })
                    .await;
                }
            }

            Command::NetUnlisten { port } => {
                if let Some(entries) = listeners.remove(&port) {
                    for entry in entries {
                        entry.task.abort();
                        let _ = entry.task.await;
                    }
                }
                respond(&Response::Ok { data: None }).await;
            }

            Command::NetConnect { addr, data } => {
                match tokio::time::timeout(
                    Duration::from_secs(5),
                    tokio::net::TcpStream::connect(&addr),
                )
                .await
                {
                    Ok(Ok(mut stream)) => {
                        let _ = stream.write_all(data.as_bytes()).await;
                        let _ = stream.flush().await;
                        let mut buf = [0u8; 4096];
                        match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
                            .await
                        {
                            Ok(Ok(n)) if n > 0 => {
                                let echo = String::from_utf8_lossy(&buf[..n]).to_string();
                                respond(&Response::Connected { echo }).await;
                            }
                            _ => {
                                respond(&Response::ConnectFailed {
                                    error: "no echo response".to_string(),
                                })
                                .await;
                            }
                        }
                    }
                    Ok(Err(e)) => {
                        respond(&Response::ConnectFailed {
                            error: format!("{e}"),
                        })
                        .await;
                    }
                    Err(_) => {
                        respond(&Response::ConnectFailed {
                            error: "connect timeout".to_string(),
                        })
                        .await;
                    }
                }
            }

            Command::NetOpen { addr } => {
                if *next_conn_id == u64::MAX {
                    respond(&Response::Error {
                        error: "connection id space exhausted".to_string(),
                    })
                    .await;
                    continue;
                }
                match tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(&addr)).await
                {
                    Ok(Ok(stream)) => {
                        let conn = *next_conn_id;
                        *next_conn_id += 1;
                        connections.insert(conn, Arc::new(tokio::sync::Mutex::new(stream)));
                        respond(&Response::Opened { conn }).await;
                    }
                    Ok(Err(e)) => {
                        respond(&Response::ConnectFailed {
                            error: format!("connect {addr}: {e}"),
                        })
                        .await;
                    }
                    Err(_) => {
                        respond(&Response::ConnectFailed {
                            error: format!("connect {addr}: timeout"),
                        })
                        .await;
                    }
                }
            }

            Command::NetSend { conn, data } => {
                let Some(stream) = connections.get(&conn).cloned() else {
                    respond(&Response::Error {
                        error: format!("unknown conn {conn}"),
                    })
                    .await;
                    continue;
                };
                let result = tokio::time::timeout(Duration::from_secs(5), async {
                    let mut stream = stream.lock().await;
                    stream
                        .write_all(data.as_bytes())
                        .await
                        .map_err(|e| format!("write conn {conn}: {e}"))?;
                    stream
                        .flush()
                        .await
                        .map_err(|e| format!("flush conn {conn}: {e}"))
                })
                .await;
                match result {
                    Ok(Ok(())) => respond(&Response::Sent).await,
                    Ok(Err(error)) => respond(&Response::Error { error }).await,
                    Err(_) => {
                        respond(&Response::Error {
                            error: format!("send conn {conn}: timeout"),
                        })
                        .await;
                    }
                }
            }

            Command::NetRecv { conn, n_bytes } => {
                let Some(stream) = connections.get(&conn).cloned() else {
                    respond(&Response::Error {
                        error: format!("unknown conn {conn}"),
                    })
                    .await;
                    continue;
                };
                let result = tokio::time::timeout(Duration::from_secs(10), async {
                    let mut stream = stream.lock().await;
                    let mut received = Vec::new();
                    match n_bytes {
                        Some(n) => {
                            received.resize(n as usize, 0);
                            stream
                                .read_exact(&mut received)
                                .await
                                .map_err(|e| format!("read_exact conn {conn}: {e}"))?;
                        }
                        None => {
                            stream
                                .read_to_end(&mut received)
                                .await
                                .map_err(|e| format!("read_to_eof conn {conn}: {e}"))?;
                        }
                    }
                    Ok::<_, String>(String::from_utf8_lossy(&received).to_string())
                })
                .await;
                match result {
                    Ok(Ok(data)) => respond(&Response::Received { data }).await,
                    Ok(Err(error)) => respond(&Response::Error { error }).await,
                    Err(_) => {
                        respond(&Response::Error {
                            error: format!("recv conn {conn}: timeout"),
                        })
                        .await;
                    }
                }
            }

            Command::NetShutdown { conn, half } => {
                let Some(stream) = connections.get(&conn).cloned() else {
                    respond(&Response::Error {
                        error: format!("unknown conn {conn}"),
                    })
                    .await;
                    continue;
                };
                let how = match half.as_str() {
                    "wr" => libc::SHUT_WR,
                    "rd" => libc::SHUT_RD,
                    "rdwr" => libc::SHUT_RDWR,
                    _ => {
                        respond(&Response::Error {
                            error: format!("invalid half {half:?}; expected wr, rd, or rdwr"),
                        })
                        .await;
                        continue;
                    }
                };
                let shutdown_result = {
                    let stream = stream.lock().await;
                    use std::os::fd::AsRawFd;
                    // SAFETY: the fd comes from a live TcpStream held by the registry,
                    // and libc::shutdown does not take ownership of it.
                    let rc = unsafe { libc::shutdown(stream.as_raw_fd(), how) };
                    if rc == 0 {
                        Ok(())
                    } else {
                        Err(format!(
                            "shutdown conn {conn}: {}",
                            std::io::Error::last_os_error()
                        ))
                    }
                };
                match shutdown_result {
                    Ok(()) => respond(&Response::ShutdownOk).await,
                    Err(error) => respond(&Response::Error { error }).await,
                }
            }

            Command::NetClose { conn } => {
                if connections.remove(&conn).is_some() {
                    respond(&Response::Closed).await;
                } else {
                    respond(&Response::Error {
                        error: format!("unknown conn {conn}"),
                    })
                    .await;
                }
            }

            Command::NetSetSockOpt {
                conn,
                option,
                value,
            } => {
                let Some(stream) = connections.get(&conn).cloned() else {
                    respond(&Response::Error {
                        error: format!("unknown conn {conn}"),
                    })
                    .await;
                    continue;
                };
                let result = {
                    let stream = stream.lock().await;
                    set_sockopt_value(stream.as_raw_fd(), option, value)
                };
                match result {
                    Ok(()) => respond(&Response::Ok { data: None }).await,
                    Err(error) => respond(&Response::Error { error }).await,
                }
            }

            Command::NetGetSockOpt { conn, option } => {
                let Some(stream) = connections.get(&conn).cloned() else {
                    respond(&Response::Error {
                        error: format!("unknown conn {conn}"),
                    })
                    .await;
                    continue;
                };
                let result = {
                    let stream = stream.lock().await;
                    get_sockopt_value(stream.as_raw_fd(), option)
                };
                match result {
                    Ok(value) => respond(&Response::SockOptResult { value }).await,
                    Err(error) => respond(&Response::Error { error }).await,
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

            Command::Run { handler, args } => {
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

            Command::WaitReady {
                agent,
                timeout_secs,
            } => {
                if agent.is_empty() || agent == "self" {
                    respond(&Response::Ready).await;
                } else if let Some(child) = children.get_mut(&agent) {
                    let timeout = Duration::from_secs(timeout_secs.unwrap_or(30));
                    let ready_cmd = Command::WaitReady {
                        agent: "self".to_string(),
                        timeout_secs,
                    };
                    let wait = send_to_child(child, &ready_cmd);
                    match tokio::time::timeout(timeout, wait).await {
                        Ok(Response::Ready) => respond(&Response::Ready).await,
                        Ok(resp) => respond(&resp).await,
                        Err(_) => {
                            respond(&Response::Error {
                                error: format!(
                                    "agent {agent} not ready within {}s",
                                    timeout.as_secs()
                                ),
                            })
                            .await;
                        }
                    }
                } else {
                    respond(&Response::Error {
                        error: format!("unknown child: {agent}"),
                    })
                    .await;
                }
            }

            Command::WaitBackground { pid, timeout_secs } => {
                let Some(bg) = background_pids.remove(&pid) else {
                    respond(&Response::Error {
                        error: format!("unknown background pid: {pid}"),
                    })
                    .await;
                    continue;
                };
                let timeout = Duration::from_secs(timeout_secs.unwrap_or(30));
                match bg {
                    BackgroundProcess::Tokio {
                        mut process,
                        stdout,
                        stderr,
                        drains,
                    } => match tokio::time::timeout(timeout, process.wait()).await {
                        Ok(Ok(status)) => {
                            for drain in drains {
                                let _ = drain.await;
                            }
                            let stdout = stdout.lock().expect("stdout buffer mutex").clone();
                            let stderr = stderr.lock().expect("stderr buffer mutex").clone();
                            respond(&Response::ExecResult {
                                exit_code: status.code().unwrap_or(-1),
                                stdout: String::from_utf8_lossy(&stdout).to_string(),
                                stderr: String::from_utf8_lossy(&stderr).to_string(),
                            })
                            .await;
                        }
                        Ok(Err(e)) => {
                            respond(&Response::Error {
                                error: format!("wait_background: {e}"),
                            })
                            .await;
                        }
                        Err(_) => {
                            let _ = process.start_kill();
                            for drain in drains {
                                drain.abort();
                            }
                            respond(&Response::ExecTimeout {
                                stderr: format!(
                                    "background process timed out after {}s",
                                    timeout.as_secs()
                                ),
                            })
                            .await;
                        }
                    },
                }
            }

            Command::WaitFor {
                predicate,
                timeout_secs,
            } => {
                let timeout = Duration::from_secs(timeout_secs.unwrap_or(30));
                let deadline = tokio::time::Instant::now() + timeout;
                loop {
                    let satisfied = match &predicate {
                        WaitPredicate::PortListening { port, host } => tokio::time::timeout(
                            Duration::from_millis(200),
                            tokio::net::TcpStream::connect(format!("{host}:{port}")),
                        )
                        .await
                        .is_ok_and(|r| r.is_ok()),
                        WaitPredicate::FileExists { path } => {
                            tokio::fs::metadata(path).await.is_ok()
                        }
                    };
                    if satisfied {
                        respond(&Response::Ready).await;
                        break;
                    }
                    if tokio::time::Instant::now() >= deadline {
                        respond(&Response::Error {
                            error: format!(
                                "wait_for {predicate:?} not satisfied within {}s",
                                timeout.as_secs()
                            ),
                        })
                        .await;
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
            }

            Command::EnvGet { var } => {
                let val = std::env::var(&var).unwrap_or_else(|_| "NOT_SET".to_string());
                respond(&Response::Ok { data: Some(val) }).await;
            }

            Command::CwdGet => {
                let cwd = std::env::current_dir()
                    .map_or_else(|e| format!("ERROR: {e}"), |p| p.display().to_string());
                respond(&Response::Ok { data: Some(cwd) }).await;
            }

            Command::UnixListen { path } => {
                let _ = tokio::fs::remove_file(&path).await;
                match tokio::net::UnixListener::bind(&path) {
                    Ok(listener) => {
                        let task = tokio::spawn(async move {
                            while let Ok((mut stream, _)) = listener.accept().await {
                                tokio::spawn(async move {
                                    let mut buf = [0u8; 4096];
                                    loop {
                                        match stream.read(&mut buf).await {
                                            Ok(0) | Err(_) => break,
                                            Ok(n) => {
                                                if stream.write_all(&buf[..n]).await.is_err() {
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                });
                            }
                        });
                        unix_listeners.insert(path.clone(), task);
                        respond(&Response::UnixListening { path }).await;
                    }
                    Err(e) => {
                        respond(&Response::Error {
                            error: format!("unix bind({path}): {e}"),
                        })
                        .await;
                    }
                }
            }

            Command::UnixUnlisten { path } => {
                if let Some(task) = unix_listeners.remove(&path) {
                    task.abort();
                }
                let _ = tokio::fs::remove_file(&path).await;
                respond(&Response::Ok { data: None }).await;
            }

            Command::UnixConnect { path, data } => {
                match tokio::time::timeout(
                    Duration::from_secs(5),
                    tokio::net::UnixStream::connect(&path),
                )
                .await
                {
                    Ok(Ok(mut stream)) => {
                        let _ = stream.write_all(data.as_bytes()).await;
                        let _ = stream.flush().await;
                        let mut buf = [0u8; 4096];
                        match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
                            .await
                        {
                            Ok(Ok(n)) if n > 0 => {
                                let echo = String::from_utf8_lossy(&buf[..n]).to_string();
                                respond(&Response::Connected { echo }).await;
                            }
                            _ => {
                                respond(&Response::ConnectFailed {
                                    error: "no echo response".to_string(),
                                })
                                .await;
                            }
                        }
                    }
                    Ok(Err(e)) => {
                        respond(&Response::ConnectFailed {
                            error: format!("{e}"),
                        })
                        .await;
                    }
                    Err(_) => {
                        respond(&Response::ConnectFailed {
                            error: "connect timeout".to_string(),
                        })
                        .await;
                    }
                }
            }

            Command::UnixPair {} => {
                if *next_unix_pair_id > u64::MAX - 2 {
                    respond(&Response::Error {
                        error: "unix pair id space exhausted".to_string(),
                    })
                    .await;
                    continue;
                }
                match create_unix_socketpair() {
                    Ok((left_fd, right_fd)) => {
                        let left = *next_unix_pair_id;
                        let right = *next_unix_pair_id + 1;
                        *next_unix_pair_id += 2;
                        unix_pairs.insert(left, left_fd);
                        unix_pairs.insert(right, right_fd);
                        respond(&Response::UnixPairHandle { left, right }).await;
                    }
                    Err(error) => respond(&Response::Error { error }).await,
                }
            }

            Command::UnixPairListen { path } => match bind_unix_pair_listener(&path) {
                Ok(listener) => {
                    unix_pair_listeners.insert(path.clone(), listener);
                    respond(&Response::UnixListening { path }).await;
                }
                Err(error) => respond(&Response::Error { error }).await,
            },

            Command::UnixPairConnect { path } => match StdUnixStream::connect(&path) {
                Ok(stream) => match register_unix_stream(stream, unix_pairs, next_unix_pair_id) {
                    Ok(id) => respond(&Response::UnixPairHandle { left: id, right: 0 }).await,
                    Err(error) => respond(&Response::Error { error }).await,
                },
                Err(e) => {
                    respond(&Response::ConnectFailed {
                        error: format!("unix connect({path}): {e}"),
                    })
                    .await;
                }
            },

            Command::UnixPairAccept { path } => {
                let Some(listener) = unix_pair_listeners.get(&path) else {
                    respond(&Response::Error {
                        error: format!("unknown unix pair listener {path}"),
                    })
                    .await;
                    continue;
                };
                match listener.accept() {
                    Ok((stream, _)) => {
                        match register_unix_stream(stream, unix_pairs, next_unix_pair_id) {
                            Ok(id) => {
                                respond(&Response::UnixPairHandle { left: id, right: 0 }).await
                            }
                            Err(error) => respond(&Response::Error { error }).await,
                        }
                    }
                    Err(e) => {
                        respond(&Response::Error {
                            error: format!("unix accept({path}): {e}"),
                        })
                        .await;
                    }
                }
            }

            Command::UnixSendFd {
                socket,
                sources,
                payload,
            } => match collect_source_fds(&sources, &eventfds, &connections, &unix_pairs).await {
                Ok(raw_fds) => {
                    let Some(sock) = unix_pairs.get(&socket) else {
                        respond(&Response::Error {
                            error: format!("unknown unix pair socket {socket}"),
                        })
                        .await;
                        continue;
                    };
                    match send_fds(sock.as_raw_fd(), &sources, &raw_fds, payload.as_bytes()) {
                        Ok(()) => respond(&Response::Sent).await,
                        Err(error) => respond(&Response::Error { error }).await,
                    }
                }
                Err(error) => respond(&Response::Error { error }).await,
            },

            Command::UnixRecvFd {
                socket,
                max_payload,
            } => {
                let Some(sock) = unix_pairs.get(&socket) else {
                    respond(&Response::Error {
                        error: format!("unknown unix pair socket {socket}"),
                    })
                    .await;
                    continue;
                };
                match recv_fds(sock.as_raw_fd(), max_payload) {
                    Ok((received, payload)) => {
                        match register_received_fds(
                            received,
                            eventfds,
                            next_eventfd_id,
                            connections,
                            next_conn_id,
                            unix_pairs,
                            next_unix_pair_id,
                        ) {
                            Ok(received) => {
                                respond(&Response::ReceivedFd { received, payload }).await
                            }
                            Err(error) => respond(&Response::Error { error }).await,
                        }
                    }
                    Err(error) => respond(&Response::Error { error }).await,
                }
            }

            Command::UnixPairClose { socket } => {
                if unix_pairs.remove(&socket).is_some() {
                    respond(&Response::Closed).await;
                } else {
                    respond(&Response::Error {
                        error: format!("unknown unix pair socket {socket}"),
                    })
                    .await;
                }
            }

            Command::Kill { pid } => {
                if let Some(child) = background_pids.remove(&pid) {
                    terminate_background(child);
                } else {
                    // SAFETY: fallback for caller-provided PID; errors are ignored.
                    unsafe {
                        libc::kill(pid as i32, libc::SIGKILL);
                    }
                }
                respond(&Response::Ok { data: None }).await;
            }

            Command::EventfdOpen { initval, flags } => {
                let id = *next_eventfd_id;
                if id == u64::MAX {
                    respond(&Response::Error {
                        error: "eventfd id space exhausted".to_string(),
                    })
                    .await;
                    continue;
                }
                match open_eventfd(initval, &flags) {
                    Ok(fd) => {
                        *next_eventfd_id += 1;
                        eventfds.insert(
                            id,
                            EventfdEntry {
                                fd,
                                flags,
                                authorized_readers: Vec::new(),
                            },
                        );
                        respond(&Response::EventfdHandle { id }).await;
                    }
                    Err(error) => respond(&Response::Error { error }).await,
                }
            }

            Command::EventfdRead { id } => {
                let Some(entry) = eventfds.get(&id) else {
                    respond(&Response::Error {
                        error: format!("unknown eventfd {id}"),
                    })
                    .await;
                    continue;
                };
                match read_eventfd_value(entry.fd.as_raw_fd()) {
                    Ok(value) => respond(&Response::EventfdValue { value }).await,
                    Err(error) => respond(&Response::Error { error }).await,
                }
            }

            Command::EventfdReadShared { id, reader } => {
                let Some(entry) = eventfds.get(&id) else {
                    respond(&Response::Error {
                        error: format!("unknown eventfd {id}"),
                    })
                    .await;
                    continue;
                };
                if !entry
                    .authorized_readers
                    .iter()
                    .any(|authorized| authorized == &reader)
                {
                    respond(&Response::Error {
                        error: format!("eventfd {id} reader {reader} is not authorized"),
                    })
                    .await;
                    continue;
                }
                match read_eventfd_value(entry.fd.as_raw_fd()) {
                    Ok(value) => respond(&Response::EventfdValue { value }).await,
                    Err(error) => respond(&Response::Error { error }).await,
                }
            }

            Command::EventfdWrite { id, value } => {
                let Some(entry) = eventfds.get(&id) else {
                    respond(&Response::Error {
                        error: format!("unknown eventfd {id}"),
                    })
                    .await;
                    continue;
                };
                match write_eventfd_value(entry.fd.as_raw_fd(), value) {
                    Ok(()) => respond(&Response::Sent).await,
                    Err(error) => respond(&Response::Error { error }).await,
                }
            }

            Command::EventfdClose { id } => {
                if eventfds.remove(&id).is_some() {
                    respond(&Response::Closed).await;
                } else {
                    respond(&Response::Error {
                        error: format!("unknown eventfd {id}"),
                    })
                    .await;
                }
            }

            Command::EventfdShare { id, target } => {
                let Some(entry) = eventfds.get_mut(&id) else {
                    respond(&Response::Error {
                        error: format!("unknown eventfd {id}"),
                    })
                    .await;
                    continue;
                };
                if !entry
                    .authorized_readers
                    .iter()
                    .any(|reader| reader == &target)
                {
                    entry.authorized_readers.push(target.clone());
                }
                // Layer 1 sharing is creator-registry based: a peer's logical
                // read is forwarded back through this creator agent. We record
                // the intended reader here, but do not pass the fd with SCM_RIGHTS.
                respond(&Response::Ok {
                    data: Some(format!(
                        "eventfd {id} shared with {target}; readers={}",
                        entry.authorized_readers.join(",")
                    )),
                })
                .await;
            }

            Command::Exit => {
                eventfds.clear();
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

fn create_unix_socketpair() -> Result<(OwnedFd, OwnedFd), String> {
    let mut sv = [0i32; 2];
    // SAFETY: `sv` points to two writable fd slots; socketpair initializes both
    // entries with fresh AF_UNIX SOCK_STREAM descriptors on success.
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
            sv.as_mut_ptr(),
        )
    } != 0
    {
        return Err(format!(
            "socketpair(AF_UNIX): {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: socketpair returned two fresh descriptors, each transferred to
    // exactly one OwnedFd for independent registry ownership.
    let left = unsafe { OwnedFd::from_raw_fd(sv[0]) };
    // SAFETY: see above; this wraps the second fresh socketpair endpoint.
    let right = unsafe { OwnedFd::from_raw_fd(sv[1]) };
    Ok((left, right))
}

fn bind_unix_pair_listener(path: &str) -> Result<StdUnixListener, String> {
    let _ = std::fs::remove_file(path);
    let listener = StdUnixListener::bind(path).map_err(|e| format!("unix bind({path}): {e}"))?;
    listener
        .set_nonblocking(false)
        .map_err(|e| format!("unix listener blocking({path}): {e}"))?;
    Ok(listener)
}

fn register_unix_stream(
    stream: StdUnixStream,
    unix_pairs: &mut HashMap<u64, OwnedFd>,
    next_unix_pair_id: &mut u64,
) -> Result<u64, String> {
    if *next_unix_pair_id == u64::MAX {
        return Err("unix pair id space exhausted".to_string());
    }
    stream
        .set_nonblocking(false)
        .map_err(|e| format!("unix stream blocking: {e}"))?;
    let id = *next_unix_pair_id;
    *next_unix_pair_id += 1;
    unix_pairs.insert(id, stream.into());
    Ok(id)
}

async fn collect_source_fds(
    sources: &[FdRef],
    eventfds: &HashMap<u64, EventfdEntry>,
    connections: &HashMap<u64, TcpConn>,
    unix_pairs: &HashMap<u64, OwnedFd>,
) -> Result<Vec<i32>, String> {
    let mut fds = Vec::with_capacity(sources.len());
    for source in sources {
        let fd = match source {
            FdRef::Eventfd(id) => eventfds
                .get(id)
                .map(|entry| entry.fd.as_raw_fd())
                .ok_or_else(|| format!("unknown eventfd {id}"))?,
            FdRef::TcpConn(id) => {
                let stream = connections
                    .get(id)
                    .cloned()
                    .ok_or_else(|| format!("unknown conn {id}"))?;
                let stream = stream.lock().await;
                stream.as_raw_fd()
            }
            FdRef::UnixPair(id) => unix_pairs
                .get(id)
                .map(AsRawFd::as_raw_fd)
                .ok_or_else(|| format!("unknown unix pair socket {id}"))?,
        };
        fds.push(fd);
    }
    Ok(fds)
}

fn fd_ref_tag(source: &FdRef) -> u8 {
    match source {
        FdRef::Eventfd(_) => b'E',
        FdRef::TcpConn(_) => b'T',
        FdRef::UnixPair(_) => b'U',
    }
}

fn send_fds(
    socket_fd: i32,
    sources: &[FdRef],
    raw_fds: &[i32],
    payload: &[u8],
) -> Result<(), String> {
    if sources.is_empty() || sources.len() != raw_fds.len() {
        return Err("unix_send_fd requires at least one source fd".to_string());
    }
    let mut tagged_payload = Vec::with_capacity(sources.len() + payload.len());
    tagged_payload.extend(sources.iter().map(fd_ref_tag));
    tagged_payload.extend_from_slice(payload);
    let mut iov = libc::iovec {
        iov_base: tagged_payload.as_mut_ptr().cast(),
        iov_len: tagged_payload.len(),
    };
    let fd_bytes = std::mem::size_of_val(raw_fds);
    // SAFETY: CMSG_SPACE only computes the buffer size for `fd_bytes` bytes of
    // control data; it does not dereference pointers.
    let mut control = vec![0u8; unsafe { libc::CMSG_SPACE(fd_bytes as u32) as usize }];
    // SAFETY: zeroed msghdr is a valid starting state; all pointer/length fields
    // used by sendmsg are initialized below before the syscall.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &raw mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = control
        .len()
        .try_into()
        .map_err(|_| "sendmsg control buffer length overflow".to_string())?;
    // SAFETY: msg has a valid control buffer large enough for the cmsg header
    // plus all source fds. CMSG_FIRSTHDR returns a pointer inside that buffer.
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() {
            return Err("CMSG_FIRSTHDR returned null".to_string());
        }
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(fd_bytes as u32)
            .try_into()
            .map_err(|_| "SCM_RIGHTS cmsg length overflow".to_string())?;
        std::ptr::copy_nonoverlapping(
            raw_fds.as_ptr().cast::<u8>(),
            libc::CMSG_DATA(cmsg).cast::<u8>(),
            fd_bytes,
        );
        msg.msg_controllen = (*cmsg).cmsg_len;
    }
    loop {
        // SAFETY: socket_fd is a live Unix stream socket; msg points to valid
        // iovec and control buffers for the duration of the call. sendmsg does
        // not take ownership of the descriptors in SCM_RIGHTS.
        let rc = unsafe { libc::sendmsg(socket_fd, &raw const msg, 0) };
        if rc == tagged_payload.len() as isize {
            return Ok(());
        }
        if rc >= 0 {
            return Err(format!(
                "sendmsg sent {rc} bytes, expected {}",
                tagged_payload.len()
            ));
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EINTR) {
            return Err(format!("sendmsg SCM_RIGHTS: {err}"));
        }
    }
}

fn recv_fds(socket_fd: i32, max_payload: u32) -> Result<(Vec<(u8, OwnedFd)>, String), String> {
    let mut data = vec![0u8; max_payload.max(1) as usize];
    let mut iov = libc::iovec {
        iov_base: data.as_mut_ptr().cast(),
        iov_len: data.len(),
    };
    let max_fds = 8usize;
    let control_len =
        unsafe { libc::CMSG_SPACE((max_fds * std::mem::size_of::<i32>()) as u32) as usize };
    let mut control = vec![0u8; control_len];
    // SAFETY: zeroed msghdr is a valid starting state; all used fields are set
    // to live data/control buffers before recvmsg.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &raw mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = control
        .len()
        .try_into()
        .map_err(|_| "recvmsg control buffer length overflow".to_string())?;
    let n = loop {
        // SAFETY: socket_fd is a live Unix stream socket; msg points to writable
        // data and control buffers. MSG_CMSG_CLOEXEC asks the kernel to set
        // close-on-exec on any received fds before they are installed.
        let rc = unsafe { libc::recvmsg(socket_fd, &raw mut msg, libc::MSG_CMSG_CLOEXEC) };
        if rc >= 0 {
            break rc as usize;
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EINTR) {
            return Err(format!("recvmsg SCM_RIGHTS: {err}"));
        }
    };
    if msg.msg_flags & libc::MSG_CTRUNC != 0 {
        return Err("recvmsg control data truncated".to_string());
    }
    if msg.msg_flags & libc::MSG_TRUNC != 0 {
        return Err("recvmsg payload truncated".to_string());
    }
    // SAFETY: msg's control buffer was filled by recvmsg. CMSG_FIRSTHDR returns
    // a pointer into that buffer or null when no control message was received.
    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    if cmsg.is_null() {
        return Err("recvmsg did not include SCM_RIGHTS cmsg".to_string());
    }
    // SAFETY: cmsg points inside msg's initialized control buffer.
    let (level, kind, cmsg_len) = unsafe {
        (
            (*cmsg).cmsg_level,
            (*cmsg).cmsg_type,
            (*cmsg).cmsg_len as usize,
        )
    };
    if level != libc::SOL_SOCKET || kind != libc::SCM_RIGHTS {
        return Err(format!("unexpected cmsg level={level} type={kind}"));
    }
    let header_len = unsafe { libc::CMSG_LEN(0) as usize };
    if cmsg_len < header_len {
        return Err(format!("short cmsg length {cmsg_len}"));
    }
    let fd_count = (cmsg_len - header_len) / std::mem::size_of::<i32>();
    if fd_count == 0 {
        return Err("SCM_RIGHTS cmsg carried no fds".to_string());
    }
    if n < fd_count {
        return Err(format!(
            "payload too short for {fd_count} fd type tags: {n} bytes"
        ));
    }
    let mut raw_fds = vec![0i32; fd_count];
    // SAFETY: CMSG_DATA points to at least fd_count i32 values per cmsg_len;
    // raw_fds is valid writable storage of the same size.
    unsafe {
        std::ptr::copy_nonoverlapping(
            libc::CMSG_DATA(cmsg).cast::<i32>(),
            raw_fds.as_mut_ptr(),
            fd_count,
        );
    }
    let tags = data[..fd_count].to_vec();
    let payload = String::from_utf8_lossy(&data[fd_count..n]).to_string();
    let received = tags
        .into_iter()
        .zip(raw_fds)
        .map(|(tag, fd)| {
            // SAFETY: each fd was freshly installed by recvmsg and is now owned
            // by this agent's registry after wrapping in OwnedFd.
            (tag, unsafe { OwnedFd::from_raw_fd(fd) })
        })
        .collect();
    Ok((received, payload))
}

fn register_received_fds(
    received: Vec<(u8, OwnedFd)>,
    eventfds: &mut HashMap<u64, EventfdEntry>,
    next_eventfd_id: &mut u64,
    connections: &mut HashMap<u64, TcpConn>,
    next_conn_id: &mut u64,
    unix_pairs: &mut HashMap<u64, OwnedFd>,
    next_unix_pair_id: &mut u64,
) -> Result<Vec<FdRef>, String> {
    let mut refs = Vec::with_capacity(received.len());
    for (tag, fd) in received {
        ensure_received_fd_cloexec(&fd)?;
        match tag {
            b'E' => {
                if *next_eventfd_id == u64::MAX {
                    return Err("eventfd id space exhausted".to_string());
                }
                let id = *next_eventfd_id;
                *next_eventfd_id += 1;
                eventfds.insert(
                    id,
                    EventfdEntry {
                        fd,
                        flags: "received_scm_rights".to_string(),
                        authorized_readers: Vec::new(),
                    },
                );
                refs.push(FdRef::Eventfd(id));
            }
            b'T' => {
                if *next_conn_id == u64::MAX {
                    return Err("connection id space exhausted".to_string());
                }
                let id = *next_conn_id;
                *next_conn_id += 1;
                // SAFETY: fd is a received TCP socket tagged by the sender and
                // uniquely owned here; from_raw_fd transfers ownership to std.
                let stream = unsafe { std::net::TcpStream::from_raw_fd(fd.into_raw_fd()) };
                stream
                    .set_nonblocking(true)
                    .map_err(|e| format!("received tcp set_nonblocking: {e}"))?;
                let stream = TcpStream::from_std(stream)
                    .map_err(|e| format!("received tcp from_std: {e}"))?;
                connections.insert(id, Arc::new(tokio::sync::Mutex::new(stream)));
                refs.push(FdRef::TcpConn(id));
            }
            b'U' => {
                if *next_unix_pair_id == u64::MAX {
                    return Err("unix pair id space exhausted".to_string());
                }
                let id = *next_unix_pair_id;
                *next_unix_pair_id += 1;
                unix_pairs.insert(id, fd);
                refs.push(FdRef::UnixPair(id));
            }
            other => return Err(format!("unknown SCM_RIGHTS fd tag byte {other}")),
        }
    }
    Ok(refs)
}

fn ensure_received_fd_cloexec(fd: &OwnedFd) -> Result<(), String> {
    // SAFETY: F_GETFD reads descriptor flags from a live fd and does not take ownership.
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
    if flags < 0 {
        return Err(format!(
            "fcntl(F_GETFD) on received fd: {}",
            std::io::Error::last_os_error()
        ));
    }
    if flags & libc::FD_CLOEXEC == 0 {
        return Err("received fd missing FD_CLOEXEC despite MSG_CMSG_CLOEXEC".to_string());
    }
    Ok(())
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

fn create_listener_entry(
    port: u16,
    pre_bind_options: &[(SockOpt, SockOptValue)],
) -> Result<(u16, ListenerEntry), String> {
    // SAFETY: socket creates a fresh descriptor on success; it is immediately
    // wrapped in OwnedFd so all later error paths close it exactly once.
    let raw_fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if raw_fd < 0 {
        return Err(format!("socket: {}", std::io::Error::last_os_error()));
    }
    // SAFETY: raw_fd was just returned by socket and is uniquely owned here.
    let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

    for &(option, value) in pre_bind_options {
        set_sockopt_value(fd.as_raw_fd(), option, value)?;
    }

    let addr = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: port.to_be(),
        sin_addr: libc::in_addr {
            s_addr: libc::INADDR_ANY,
        },
        sin_zero: [0; 8],
    };
    // SAFETY: addr points to a valid IPv4 sockaddr for the duration of the
    // call, and fd is a live TCP socket not aliased mutably elsewhere.
    let bind_rc = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            std::ptr::addr_of!(addr).cast::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if bind_rc != 0 {
        return Err(format!("bind: {}", std::io::Error::last_os_error()));
    }
    // SAFETY: fd is a live bound TCP socket; listen does not take ownership.
    let listen_rc = unsafe { libc::listen(fd.as_raw_fd(), 128) };
    if listen_rc != 0 {
        return Err(format!("listen: {}", std::io::Error::last_os_error()));
    }

    // SAFETY: fd is a live listening socket; zeroed sockaddr_in is an acceptable
    // output buffer for getsockname, which initializes len bytes on success.
    let mut actual_addr = unsafe { std::mem::zeroed::<libc::sockaddr_in>() };
    let mut actual_len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    // SAFETY: actual_addr and actual_len point to writable storage valid for
    // the call; fd remains owned by this function.
    let name_rc = unsafe {
        libc::getsockname(
            fd.as_raw_fd(),
            std::ptr::addr_of_mut!(actual_addr).cast::<libc::sockaddr>(),
            &mut actual_len,
        )
    };
    let actual_port = if name_rc == 0 {
        u16::from_be(actual_addr.sin_port)
    } else {
        port
    };

    // SAFETY: into_raw_fd transfers the uniquely owned listening socket to the
    // standard library TcpListener, which now closes it on drop.
    let std_listener = unsafe { std::net::TcpListener::from_raw_fd(fd.into_raw_fd()) };
    std_listener
        .set_nonblocking(true)
        .map_err(|e| format!("set_nonblocking: {e}"))?;
    let registry_fd = dup_fd_cloexec(std_listener.as_raw_fd())?;
    let accepted = Arc::new(AtomicUsize::new(0));
    let task = spawn_tcp_echo_task(std_listener, accepted.clone())?;
    Ok((
        actual_port,
        ListenerEntry {
            fd: registry_fd,
            task,
            accepted,
        },
    ))
}

fn spawn_tcp_echo_task(
    std_listener: std::net::TcpListener,
    accepted: Arc<AtomicUsize>,
) -> Result<tokio::task::JoinHandle<()>, String> {
    let listener = TcpListener::from_std(std_listener).map_err(|e| format!("from_std: {e}"))?;
    Ok(tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            accepted.fetch_add(1, Ordering::Relaxed);
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if stream.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    }))
}

fn sockopt_level_name(option: SockOpt) -> (i32, i32, &'static str, bool) {
    match option {
        SockOpt::ReuseAddr => (libc::SOL_SOCKET, libc::SO_REUSEADDR, "SO_REUSEADDR", true),
        SockOpt::ReusePort => (libc::SOL_SOCKET, libc::SO_REUSEPORT, "SO_REUSEPORT", true),
        SockOpt::KeepAlive => (libc::SOL_SOCKET, libc::SO_KEEPALIVE, "SO_KEEPALIVE", true),
        SockOpt::RecvBuf => (libc::SOL_SOCKET, libc::SO_RCVBUF, "SO_RCVBUF", false),
        SockOpt::SendBuf => (libc::SOL_SOCKET, libc::SO_SNDBUF, "SO_SNDBUF", false),
        SockOpt::NoDelay => (libc::IPPROTO_TCP, libc::TCP_NODELAY, "TCP_NODELAY", true),
    }
}

fn set_sockopt_value(fd: i32, option: SockOpt, value: SockOptValue) -> Result<(), String> {
    let (level, optname, name, _) = sockopt_level_name(option);
    let raw: libc::c_int = match value {
        SockOptValue::Bool(enabled) => i32::from(enabled),
        SockOptValue::U32(value) => value as libc::c_int,
    };
    // SAFETY: fd is a live socket descriptor owned by the agent registry; raw
    // points to a properly aligned c_int value for the duration of the call.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            optname,
            std::ptr::addr_of!(raw).cast::<libc::c_void>(),
            std::mem::size_of_val(&raw) as libc::socklen_t,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(format!(
            "setsockopt {name}: {}",
            std::io::Error::last_os_error()
        ))
    }
}

fn get_sockopt_value(fd: i32, option: SockOpt) -> Result<SockOptValue, String> {
    let (level, optname, name, is_bool) = sockopt_level_name(option);
    let mut raw: libc::c_int = 0;
    let mut len = std::mem::size_of_val(&raw) as libc::socklen_t;
    // SAFETY: fd is a live socket descriptor owned by the agent registry; raw
    // and len point to writable storage valid for the duration of the call.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            level,
            optname,
            std::ptr::addr_of_mut!(raw).cast::<libc::c_void>(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(format!(
            "getsockopt {name}: {}",
            std::io::Error::last_os_error()
        ));
    }
    if is_bool {
        Ok(SockOptValue::Bool(raw != 0))
    } else {
        Ok(SockOptValue::U32(raw.max(0) as u32))
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
    for (index, port) in ports.iter().copied().enumerate() {
        let entry = listeners
            .get(&port)
            .and_then(|entries| entries.first())
            .ok_or_else(|| format!("no listener registered for port {port}"))?;
        let slot = INHERITED_LISTEN_FD_BASE + index as i32;
        inherited.push((port, dup_fd_to_inherited_slot(entry.fd.as_raw_fd(), slot)?));
    }
    Ok(inherited)
}

fn parse_eventfd_flags(flags: &str) -> Result<i32, String> {
    let mut bits = 0;
    for raw in flags.split('|') {
        let flag = raw.trim();
        if flag.is_empty() {
            continue;
        }
        match flag.to_ascii_lowercase().as_str() {
            "semaphore" | "efd_semaphore" => bits |= libc::EFD_SEMAPHORE,
            "nonblock" | "efd_nonblock" => bits |= libc::EFD_NONBLOCK,
            "cloexec" | "efd_cloexec" => bits |= libc::EFD_CLOEXEC,
            other => return Err(format!("unknown eventfd flag {other:?}")),
        }
    }
    Ok(bits)
}

fn open_eventfd(initval: u64, flags: &str) -> Result<OwnedFd, String> {
    let init = u32::try_from(initval)
        .map_err(|_| format!("eventfd initval {initval} exceeds u32::MAX"))?;
    let flag_bits = parse_eventfd_flags(flags)?;
    // SAFETY: eventfd creates a new file descriptor and does not alias memory.
    let fd = unsafe { libc::eventfd(init, flag_bits) };
    if fd < 0 {
        return Err(format!(
            "eventfd(initval={initval}, flags={flags:?}): {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: `fd` is a newly returned descriptor owned by this process.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn read_eventfd_value(fd: i32) -> Result<u64, String> {
    let mut value = 0u64;
    loop {
        // SAFETY: `value` points to valid writable memory for exactly 8 bytes;
        // eventfd read does not take ownership of `fd`.
        let rc = unsafe {
            libc::read(
                fd,
                (&raw mut value).cast::<libc::c_void>(),
                std::mem::size_of::<u64>(),
            )
        };
        if rc == std::mem::size_of::<u64>() as isize {
            return Ok(value);
        }
        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::EINTR) => continue,
            Some(libc::EAGAIN) => return Err("eventfd read: EAGAIN".to_string()),
            _ => return Err(format!("eventfd read: {err}")),
        }
    }
}

fn write_eventfd_value(fd: i32, value: u64) -> Result<(), String> {
    loop {
        // SAFETY: `value` points to valid readable memory for exactly 8 bytes;
        // eventfd write does not take ownership of `fd`.
        let rc = unsafe {
            libc::write(
                fd,
                (&raw const value).cast::<libc::c_void>(),
                std::mem::size_of::<u64>(),
            )
        };
        if rc == std::mem::size_of::<u64>() as isize {
            return Ok(());
        }
        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::EINTR) => continue,
            Some(libc::EAGAIN) => return Err("eventfd write: EAGAIN".to_string()),
            _ => return Err(format!("eventfd write value={value}: {err}")),
        }
    }
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

    let mut line = String::new();
    match tokio::time::timeout(Duration::from_secs(60), child.stdout.read_line(&mut line)).await {
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
