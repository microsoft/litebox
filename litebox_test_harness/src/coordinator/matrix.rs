// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Declarative test matrix — drives "cover all configurations" tests via
// structured loops over typed dimensions.
//
// Dimensions:
// - **Topology**: (source, dest) agent pairs in the process tree, including init
// - **FsScope**: /shared (visible) vs /tmp (isolated)
// - **SymlinkVariant**: basic, directory, dangling, nested, relative
// - **UnixPattern**: in-process, server+fork-client, background-server, cross-agent
// - **UnixDepth**: which agent depth runs the pattern
//
// Note: `init` (the coordinator) is a first-class node in the process tree for
// FS tests (it handles FsRead/FsWrite/FsDelete/FsSymlink/FsReadlink/FsStat/
// NetConnect locally). It cannot listen on TCP or Unix sockets.

use super::agents::{AgentHandle, AgentName};
use super::registry::Registry;
use super::run_context::RunContext;
use crate::handlers::{HandlerCtx, HandlerToken};
use crate::protocol::Response;
use crate::register_handler;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;

use std::process::Stdio;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Clone, Serialize, Deserialize)]
struct FsPathArgs {
    path: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct FsWriteArgs {
    path: String,
    data: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct FsSymlinkArgs {
    target: String,
    link: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct NetListenArgs {
    port: u16,
}

#[derive(Clone, Serialize, Deserialize)]
struct NetConnectArgs {
    addr: String,
    data: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct UnixConnectArgs {
    path: String,
    data: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct ExecArgs {
    args: Vec<String>,
    timeout_secs: Option<u64>,
    stdin: Option<String>,
    background: bool,
    env: Vec<(String, String)>,
}

#[derive(Clone, Serialize, Deserialize)]
struct ExecReadyArgs {
    args: Vec<String>,
    ready_marker: String,
    timeout_secs: Option<u64>,
    stdin: Option<String>,
    stream: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct KillArgs {
    pid: u32,
}

#[derive(Clone, Serialize, Deserialize)]
struct EnvGetArgs {
    var: String,
}

const FS_READ: HandlerToken<FsPathArgs, Response> = HandlerToken::new("matrix.fs_read");
const FS_WRITE: HandlerToken<FsWriteArgs, Response> = HandlerToken::new("matrix.fs_write");
const FS_DELETE: HandlerToken<FsPathArgs, Response> = HandlerToken::new("matrix.fs_delete");
const FS_SYMLINK: HandlerToken<FsSymlinkArgs, Response> = HandlerToken::new("matrix.fs_symlink");
const FS_READLINK: HandlerToken<FsPathArgs, Response> = HandlerToken::new("matrix.fs_readlink");
const FS_STAT: HandlerToken<FsPathArgs, Response> = HandlerToken::new("matrix.fs_stat");
const NET_LISTEN: HandlerToken<NetListenArgs, Response> = HandlerToken::new("matrix.net_listen");
const NET_UNLISTEN: HandlerToken<NetListenArgs, Response> =
    HandlerToken::new("matrix.net_unlisten");
const NET_CONNECT: HandlerToken<NetConnectArgs, Response> = HandlerToken::new("matrix.net_connect");
const UNIX_LISTEN: HandlerToken<FsPathArgs, Response> = HandlerToken::new("matrix.unix_listen");
const UNIX_UNLISTEN: HandlerToken<FsPathArgs, Response> = HandlerToken::new("matrix.unix_unlisten");
const UNIX_CONNECT: HandlerToken<UnixConnectArgs, Response> =
    HandlerToken::new("matrix.unix_connect");
const EXEC: HandlerToken<ExecArgs, Response> = HandlerToken::new("matrix.exec");
const EXEC_READY: HandlerToken<ExecReadyArgs, Response> = HandlerToken::new("matrix.exec_ready");
const KILL: HandlerToken<KillArgs, Response> = HandlerToken::new("matrix.kill");
const ENV_GET: HandlerToken<EnvGetArgs, Response> = HandlerToken::new("matrix.env_get");
const CWD_GET: HandlerToken<(), Response> = HandlerToken::new("matrix.cwd_get");

static TCP_LISTENERS: OnceLock<Mutex<HashMap<u16, tokio::task::JoinHandle<()>>>> = OnceLock::new();
static UNIX_LISTENERS: OnceLock<Mutex<HashMap<String, tokio::task::JoinHandle<()>>>> =
    OnceLock::new();

fn tcp_listeners() -> &'static Mutex<HashMap<u16, tokio::task::JoinHandle<()>>> {
    TCP_LISTENERS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn unix_listeners() -> &'static Mutex<HashMap<String, tokio::task::JoinHandle<()>>> {
    UNIX_LISTENERS.get_or_init(|| Mutex::new(HashMap::new()))
}

async fn local_fs_read(args: FsPathArgs) -> Response {
    match tokio::fs::read_to_string(&args.path).await {
        Ok(data) => Response::Ok { data: Some(data) },
        Err(_) => Response::NotFound,
    }
}

async fn local_fs_write(args: FsWriteArgs) -> Response {
    if let Some(parent) = std::path::Path::new(&args.path).parent() {
        let _ = tokio::fs::create_dir_all(parent).await;
    }
    match tokio::fs::write(&args.path, &args.data).await {
        Ok(()) => Response::Ok { data: None },
        Err(e) => Response::Error {
            error: format!("write: {e}"),
        },
    }
}

async fn local_fs_delete(args: FsPathArgs) -> Response {
    match tokio::fs::remove_file(&args.path).await {
        Ok(()) => Response::Ok { data: None },
        Err(e) => Response::Error {
            error: format!("delete: {e}"),
        },
    }
}

async fn local_fs_symlink(args: FsSymlinkArgs) -> Response {
    match tokio::fs::symlink(&args.target, &args.link).await {
        Ok(()) => Response::Ok { data: None },
        Err(e) => Response::Error {
            error: format!("symlink: {e}"),
        },
    }
}

async fn local_fs_readlink(args: FsPathArgs) -> Response {
    match tokio::fs::read_link(&args.path).await {
        Ok(target) => Response::Ok {
            data: Some(target.to_string_lossy().into_owned()),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Response::NotFound,
        Err(e) => Response::Error {
            error: format!("readlink: {e}"),
        },
    }
}

async fn local_fs_stat(args: FsPathArgs) -> Response {
    match tokio::fs::symlink_metadata(&args.path).await {
        Ok(meta) => {
            let kind = if meta.is_symlink() {
                "symlink"
            } else if meta.is_dir() {
                "dir"
            } else {
                "file"
            };
            Response::Ok {
                data: Some(kind.to_string()),
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Response::NotFound,
        Err(e) => Response::Error {
            error: format!("stat: {e}"),
        },
    }
}

async fn local_net_listen(args: NetListenArgs) -> Response {
    match tokio::net::TcpListener::bind((std::net::Ipv4Addr::UNSPECIFIED, args.port)).await {
        Ok(listener) => {
            let port = match listener.local_addr() {
                Ok(addr) => addr.port(),
                Err(e) => {
                    return Response::Error {
                        error: format!("local_addr: {e}"),
                    };
                }
            };
            let task = tokio::spawn(async move {
                while let Ok((mut stream, _)) = listener.accept().await {
                    tokio::spawn(async move {
                        let mut buf = [0_u8; 4096];
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
            if let Some(old) = tcp_listeners()
                .lock()
                .expect("tcp listener registry poisoned")
                .insert(port, task)
            {
                old.abort();
            }
            Response::Listening { port }
        }
        Err(e) => Response::Error {
            error: format!("bind {}: {e}", args.port),
        },
    }
}

async fn local_net_unlisten(args: NetListenArgs) -> Response {
    if let Some(task) = tcp_listeners()
        .lock()
        .expect("tcp listener registry poisoned")
        .remove(&args.port)
    {
        task.abort();
    }
    Response::Ok { data: None }
}

async fn local_net_connect(args: NetConnectArgs) -> Response {
    match tokio::time::timeout(
        Duration::from_secs(5),
        tokio::net::TcpStream::connect(&args.addr),
    )
    .await
    {
        Ok(Ok(mut stream)) => {
            let _ = stream.write_all(args.data.as_bytes()).await;
            let _ = stream.flush().await;
            let mut buf = [0_u8; 4096];
            match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => Response::Connected {
                    echo: String::from_utf8_lossy(&buf[..n]).to_string(),
                },
                _ => Response::ConnectFailed {
                    error: "no echo response".to_string(),
                },
            }
        }
        Ok(Err(e)) => Response::ConnectFailed {
            error: format!("{e}"),
        },
        Err(_) => Response::ConnectFailed {
            error: "connect timeout".to_string(),
        },
    }
}

async fn local_unix_listen(args: FsPathArgs) -> Response {
    let _ = tokio::fs::remove_file(&args.path).await;
    match tokio::net::UnixListener::bind(&args.path) {
        Ok(listener) => {
            let path = args.path;
            let task = tokio::spawn(async move {
                while let Ok((mut stream, _)) = listener.accept().await {
                    tokio::spawn(async move {
                        let mut buf = [0_u8; 4096];
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
            if let Some(old) = unix_listeners()
                .lock()
                .expect("unix listener registry poisoned")
                .insert(path.clone(), task)
            {
                old.abort();
            }
            Response::UnixListening { path }
        }
        Err(e) => Response::Error {
            error: format!("unix bind({}): {e}", args.path),
        },
    }
}

async fn local_unix_unlisten(args: FsPathArgs) -> Response {
    if let Some(task) = unix_listeners()
        .lock()
        .expect("unix listener registry poisoned")
        .remove(&args.path)
    {
        task.abort();
    }
    let _ = tokio::fs::remove_file(&args.path).await;
    Response::Ok { data: None }
}

async fn local_unix_connect(args: UnixConnectArgs) -> Response {
    match tokio::time::timeout(
        Duration::from_secs(5),
        tokio::net::UnixStream::connect(&args.path),
    )
    .await
    {
        Ok(Ok(mut stream)) => {
            let _ = stream.write_all(args.data.as_bytes()).await;
            let _ = stream.flush().await;
            let mut buf = [0_u8; 4096];
            match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => Response::Connected {
                    echo: String::from_utf8_lossy(&buf[..n]).to_string(),
                },
                _ => Response::ConnectFailed {
                    error: "no echo response".to_string(),
                },
            }
        }
        Ok(Err(e)) => Response::ConnectFailed {
            error: format!("{e}"),
        },
        Err(_) => Response::ConnectFailed {
            error: "connect timeout".to_string(),
        },
    }
}

async fn local_exec(args: ExecArgs) -> Response {
    if args.args.is_empty() {
        return Response::Error {
            error: "exec requires args".to_string(),
        };
    }
    let mut cmd = tokio::process::Command::new(&args.args[0]);
    cmd.args(&args.args[1..]);
    for (key, value) in &args.env {
        cmd.env(key, value);
    }
    if args.stdin.is_some() {
        cmd.stdin(Stdio::piped());
    } else {
        cmd.stdin(Stdio::null());
    }
    if args.background {
        cmd.stdout(Stdio::null()).stderr(Stdio::null());
        match cmd.spawn() {
            Ok(mut child) => {
                if let Some(content) = args.stdin
                    && let Some(mut stdin) = child.stdin.take()
                {
                    let _ = stdin.write_all(content.as_bytes()).await;
                }
                Response::Background {
                    pid: child.id().unwrap_or(0),
                }
            }
            Err(e) => Response::Error {
                error: format!("exec spawn: {e}"),
            },
        }
    } else {
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = match cmd.spawn() {
            Ok(child) => child,
            Err(e) => {
                return Response::Error {
                    error: format!("exec spawn: {e}"),
                };
            }
        };
        if let Some(content) = args.stdin
            && let Some(mut stdin) = child.stdin.take()
        {
            let _ = stdin.write_all(content.as_bytes()).await;
        }
        let timeout = Duration::from_secs(args.timeout_secs.unwrap_or(10));
        match tokio::time::timeout(timeout, child.wait_with_output()).await {
            Ok(Ok(output)) => Response::ExecResult {
                exit_code: output.status.code().unwrap_or(-1),
                stdout: String::from_utf8_lossy(&output.stdout).to_string(),
                stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            },
            Ok(Err(e)) => Response::Error {
                error: format!("exec wait: {e}"),
            },
            Err(_) => Response::ExecTimeout {
                stderr: format!(
                    "process timed out after {}s (likely deadlocked)",
                    timeout.as_secs()
                ),
            },
        }
    }
}

#[allow(clippy::too_many_lines)]
async fn local_exec_ready(args: ExecReadyArgs) -> Response {
    if args.args.is_empty() {
        return Response::Error {
            error: "exec_ready requires args".to_string(),
        };
    }
    if !matches!(args.stream.as_str(), "stdout" | "stderr" | "either") {
        return Response::Error {
            error: format!(
                "invalid marker stream {:?}; expected stdout, stderr, or either",
                args.stream
            ),
        };
    }
    let mut cmd = std::process::Command::new(&args.args[0]);
    cmd.args(&args.args[1..]);
    if args.stdin.is_some() {
        cmd.stdin(Stdio::piped());
    } else {
        cmd.stdin(Stdio::null());
    }
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => {
            return Response::Error {
                error: format!("exec_ready spawn: {e}"),
            };
        }
    };
    if let Some(content) = args.stdin
        && let Some(mut stdin) = child.stdin.take()
    {
        let _ = std::io::Write::write_all(&mut stdin, content.as_bytes());
    }
    let Some(stdout) = child.stdout.take() else {
        return Response::Error {
            error: "exec_ready: stdout pipe missing".to_string(),
        };
    };
    let Some(stderr) = child.stderr.take() else {
        return Response::Error {
            error: "exec_ready: stderr pipe missing".to_string(),
        };
    };
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    let marker = args.ready_marker.clone();
    let stream = args.stream.clone();
    if matches!(stream.as_str(), "stdout" | "either") {
        let tx = tx.clone();
        let marker = marker.clone();
        std::thread::spawn(move || {
            let mut reader = std::io::BufReader::new(stdout);
            let mut seen = Vec::new();
            let mut byte = [0_u8; 1];
            while let Ok(1) = std::io::Read::read(&mut reader, &mut byte) {
                seen.push(byte[0]);
                if String::from_utf8_lossy(&seen).contains(&marker) {
                    let _ = tx.send("ready".to_string());
                    break;
                }
            }
        });
    }
    if matches!(stream.as_str(), "stderr" | "either") {
        let tx = tx.clone();
        let marker = marker.clone();
        std::thread::spawn(move || {
            let mut reader = std::io::BufReader::new(stderr);
            let mut seen = Vec::new();
            let mut byte = [0_u8; 1];
            while let Ok(1) = std::io::Read::read(&mut reader, &mut byte) {
                seen.push(byte[0]);
                if String::from_utf8_lossy(&seen).contains(&marker) {
                    let _ = tx.send("ready".to_string());
                    break;
                }
            }
        });
    }
    let timeout = Duration::from_secs(args.timeout_secs.unwrap_or(30));
    let start = Instant::now();
    loop {
        if rx.try_recv().is_ok() {
            let pid = child.id();
            std::mem::forget(child);
            return Response::BackgroundReady { pid };
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                return Response::Error {
                    error: format!("process exited before ready_marker (status={status})"),
                };
            }
            Ok(None) => {}
            Err(e) => {
                return Response::Error {
                    error: format!("exec_ready poll: {e}"),
                };
            }
        }
        if start.elapsed() >= timeout {
            let _ = child.kill();
            return Response::Error {
                error: format!("ready_marker not observed within {}s", timeout.as_secs()),
            };
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

async fn local_kill(args: KillArgs) -> Response {
    let Ok(pid) = libc::pid_t::try_from(args.pid) else {
        return Response::Error {
            error: format!("kill {}: pid out of range", args.pid),
        };
    };
    // SAFETY: libc::kill is called with a PID returned by a previous background spawn and a constant signal.
    let rc = unsafe { libc::kill(pid, libc::SIGKILL) };
    if rc == 0 {
        Response::Ok { data: None }
    } else {
        Response::Error {
            error: format!("kill {}: {}", args.pid, std::io::Error::last_os_error()),
        }
    }
}

async fn local_env_get(args: EnvGetArgs) -> Response {
    Response::Ok {
        data: Some(std::env::var(&args.var).unwrap_or_else(|_| "NOT_SET".to_string())),
    }
}

#[allow(clippy::unused_async)]
async fn local_cwd_get((): ()) -> Response {
    Response::Ok {
        data: Some(
            std::env::current_dir()
                .map_or_else(|e| format!("ERROR: {e}"), |p| p.display().to_string()),
        ),
    }
}

async fn handle_fs_read(
    args: FsPathArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<Response, crate::handlers::HandlerError> {
    Ok(local_fs_read(args).await)
}
async fn handle_fs_write(
    args: FsWriteArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<Response, crate::handlers::HandlerError> {
    Ok(local_fs_write(args).await)
}
async fn handle_fs_delete(
    args: FsPathArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<Response, crate::handlers::HandlerError> {
    Ok(local_fs_delete(args).await)
}
async fn handle_fs_symlink(
    args: FsSymlinkArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<Response, crate::handlers::HandlerError> {
    Ok(local_fs_symlink(args).await)
}
async fn handle_fs_readlink(
    args: FsPathArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<Response, crate::handlers::HandlerError> {
    Ok(local_fs_readlink(args).await)
}
async fn handle_fs_stat(
    args: FsPathArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<Response, crate::handlers::HandlerError> {
    Ok(local_fs_stat(args).await)
}
async fn handle_net_listen(
    args: NetListenArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<Response, crate::handlers::HandlerError> {
    Ok(local_net_listen(args).await)
}
async fn handle_net_unlisten(
    args: NetListenArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<Response, crate::handlers::HandlerError> {
    Ok(local_net_unlisten(args).await)
}
async fn handle_net_connect(
    args: NetConnectArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<Response, crate::handlers::HandlerError> {
    Ok(local_net_connect(args).await)
}
async fn handle_unix_listen(
    args: FsPathArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<Response, crate::handlers::HandlerError> {
    Ok(local_unix_listen(args).await)
}
async fn handle_unix_unlisten(
    args: FsPathArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<Response, crate::handlers::HandlerError> {
    Ok(local_unix_unlisten(args).await)
}
async fn handle_unix_connect(
    args: UnixConnectArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<Response, crate::handlers::HandlerError> {
    Ok(local_unix_connect(args).await)
}
async fn handle_exec(
    args: ExecArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<Response, crate::handlers::HandlerError> {
    Ok(local_exec(args).await)
}
async fn handle_exec_ready(
    args: ExecReadyArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<Response, crate::handlers::HandlerError> {
    Ok(local_exec_ready(args).await)
}
async fn handle_kill(
    args: KillArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<Response, crate::handlers::HandlerError> {
    Ok(local_kill(args).await)
}
async fn handle_env_get(
    args: EnvGetArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<Response, crate::handlers::HandlerError> {
    Ok(local_env_get(args).await)
}
async fn handle_cwd_get(
    args: (),
    _ctx: &mut HandlerCtx<'_>,
) -> Result<Response, crate::handlers::HandlerError> {
    Ok(local_cwd_get(args).await)
}

fn register_matrix_handlers() {
    register_handler!(FS_READ, handle_fs_read);
    register_handler!(FS_WRITE, handle_fs_write);
    register_handler!(FS_DELETE, handle_fs_delete);
    register_handler!(FS_SYMLINK, handle_fs_symlink);
    register_handler!(FS_READLINK, handle_fs_readlink);
    register_handler!(FS_STAT, handle_fs_stat);
    register_handler!(NET_LISTEN, handle_net_listen);
    register_handler!(NET_UNLISTEN, handle_net_unlisten);
    register_handler!(NET_CONNECT, handle_net_connect);
    register_handler!(UNIX_LISTEN, handle_unix_listen);
    register_handler!(UNIX_UNLISTEN, handle_unix_unlisten);
    register_handler!(UNIX_CONNECT, handle_unix_connect);
    register_handler!(EXEC, handle_exec);
    register_handler!(EXEC_READY, handle_exec_ready);
    register_handler!(KILL, handle_kill);
    register_handler!(ENV_GET, handle_env_get);
    register_handler!(CWD_GET, handle_cwd_get);
}

async fn send_response<A, F, Fut>(
    run: &mut RunContext<'_>,
    handles: &MatrixHandles,
    agent: AgentName,
    token: &HandlerToken<A, Response>,
    args: A,
    local: F,
) -> Response
where
    A: Clone + Serialize,
    F: FnOnce(A) -> Fut,
    Fut: Future<Output = Response>,
{
    if agent == AgentName::Init {
        local(args).await
    } else {
        run.send_named_typed(handle_for(handles, agent), token, args)
            .await
            .unwrap_or_else(|error| Response::Error { error })
    }
}

#[allow(clippy::large_enum_variant, dead_code)]
enum MatrixOp {
    FsRead {
        path: String,
    },
    FsWrite {
        path: String,
        data: String,
    },
    FsDelete {
        path: String,
    },
    FsSymlink {
        target: String,
        link: String,
    },
    FsReadlink {
        path: String,
    },
    FsStat {
        path: String,
    },
    NetListen {
        port: u16,
        pre_bind_options: Vec<()>,
    },
    NetUnlisten {
        port: u16,
    },
    NetConnect {
        addr: String,
        data: String,
    },
    UnixListen {
        path: String,
    },
    UnixUnlisten {
        path: String,
    },
    UnixConnect {
        path: String,
        data: String,
    },
    Exec {
        args: Vec<String>,
        timeout_secs: Option<u64>,
        stdin: Option<String>,
        background: bool,
        env: Vec<(String, String)>,
    },
    ExecReady {
        args: Vec<String>,
        ready_marker: String,
        timeout_secs: Option<u64>,
        stdin: Option<String>,
        stream: String,
    },
    Kill {
        pid: u32,
    },
    EnvGet {
        var: String,
    },
    CwdGet,
}

fn exec(args: Vec<String>) -> MatrixOp {
    MatrixOp::Exec {
        args,
        timeout_secs: None,
        stdin: None,
        background: false,
        env: vec![],
    }
}

// ── Topology axis ──

/// A relationship between two agents in the process tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Topology {
    /// Same agent (A writes, A reads).
    InProcess,
    /// init → A.
    ParentToChild,
    /// A → init.
    ChildToParent,
    /// A → B.
    Sibling,
    /// B → A.
    SiblingReverse,
    /// AA → init.
    GrandchildUp,
    /// AAA → init.
    GreatGrandchildUp,
    /// B → AAA.
    #[allow(dead_code)]
    CrossSubtree,
    /// AA → AB.
    #[allow(dead_code)]
    SiblingDepth2,
    /// AAA → AAB.
    #[allow(dead_code)]
    SiblingDepth3,
    /// AB → B.
    #[allow(dead_code)]
    Uncle,
    /// A → NP (non-PIE child via `SpawnRemote`).
    PieToNonPie,
    /// NP → A (non-PIE writes, PIE reads).
    NonPieToParent,
    /// NPC → A (PIE-from-non-PIE reads, PIE reads).
    NonPieChildUp,
    /// D5 → B (depth 5 from non-PIE root, cross-subtree).
    DeepNonPie,
}

impl Topology {
    fn agents(self) -> (AgentName, AgentName) {
        match self {
            Self::InProcess => (AgentName::Dpg1, AgentName::Dpg1),
            Self::ParentToChild => (AgentName::Init, AgentName::Dpg1),
            Self::ChildToParent => (AgentName::Dpg1, AgentName::Init),
            Self::Sibling => (AgentName::Dpg1, AgentName::Dpg2),
            Self::SiblingReverse => (AgentName::Dpg2, AgentName::Dpg1),
            Self::GrandchildUp => (AgentName::Dpg1Dpg1, AgentName::Init),
            Self::GreatGrandchildUp => (AgentName::Dpg1Dpg1Dpg1, AgentName::Init),
            Self::CrossSubtree => (AgentName::Dpg2, AgentName::Dpg1Dpg1Dpg1),
            Self::SiblingDepth2 => (AgentName::Dpg1Dpg1, AgentName::Dpg1Dpg2),
            Self::SiblingDepth3 => (AgentName::Dpg1Dpg1Dpg1, AgentName::Dpg1Dpg1Dpg2),
            Self::Uncle => (AgentName::Dpg1Dpg2, AgentName::Dpg2),
            Self::PieToNonPie => (AgentName::Dpg1, AgentName::Dpg1Dng),
            Self::NonPieToParent => (AgentName::Dpg1Dng, AgentName::Dpg1),
            Self::NonPieChildUp => (AgentName::Dpg1DngDpg, AgentName::Dpg1),
            Self::DeepNonPie => (AgentName::Dpg1DngDpg, AgentName::Dpg2),
        }
    }

    fn suffix(self) -> &'static str {
        match self {
            Self::InProcess => "in_process",
            Self::ParentToChild => "parent_to_child",
            Self::ChildToParent => "child_to_parent",
            Self::Sibling => "sibling",
            Self::SiblingReverse => "sibling_rev",
            Self::GrandchildUp => "grandchild_up",
            Self::GreatGrandchildUp => "great_grandchild_up",
            Self::CrossSubtree => "cross_subtree",
            Self::SiblingDepth2 => "sibling_d2",
            Self::SiblingDepth3 => "sibling_d3",
            Self::Uncle => "uncle",
            Self::PieToNonPie => "pie_to_nonpie",
            Self::NonPieToParent => "nonpie_to_parent",
            Self::NonPieChildUp => "nonpie_child_up",
            Self::DeepNonPie => "deep_nonpie",
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// FILESYSTEM
// ═══════════════════════════════════════════════════════════════════

const FS_TOPOLOGIES: &[Topology] = &[
    Topology::ParentToChild,
    Topology::ChildToParent,
    Topology::Sibling,
    Topology::SiblingReverse,
    Topology::GrandchildUp,
    Topology::GreatGrandchildUp,
    Topology::PieToNonPie,
    Topology::NonPieToParent,
    Topology::NonPieChildUp,
    Topology::DeepNonPie,
];

/// Scope dimension for filesystem tests.
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
enum FsScope {
    /// /shared — visible across all agents.
    Shared,
    /// /tmp — may be isolated per-agent.
    TmpIsolated,
}

#[allow(dead_code)]
impl FsScope {
    fn prefix(self) -> &'static str {
        match self {
            Self::Shared => "/shared",
            Self::TmpIsolated => "/tmp",
        }
    }

    fn suffix(self) -> &'static str {
        match self {
            Self::Shared => "shared",
            Self::TmpIsolated => "tmp",
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// NETWORK
// ═══════════════════════════════════════════════════════════════════

/// Net test descriptor. Listener listens, connector connects.
struct NetTestCase {
    name: &'static str,
    listener: AgentName,
    connector: AgentName,
}

/// Net test with explicit connect address (to test cross-worker routing).
#[allow(dead_code)]
struct NetAddrTestCase {
    name: &'static str,
    listener: AgentName,
    connector: AgentName,
    /// Address the connector uses: "127.0.0.1", "10.0.0.2", or "0.0.0.0".
    connect_addr: &'static str,
}

const NET_TESTS: &[NetTestCase] = &[
    NetTestCase {
        name: "init_to_A",
        listener: AgentName::Dpg1,
        connector: AgentName::Init,
    },
    NetTestCase {
        name: "A_to_B",
        listener: AgentName::Dpg2,
        connector: AgentName::Dpg1,
    },
    NetTestCase {
        name: "B_to_A",
        listener: AgentName::Dpg1,
        connector: AgentName::Dpg2,
    },
    NetTestCase {
        name: "AAA_to_A",
        listener: AgentName::Dpg1,
        connector: AgentName::Dpg1Dpg1Dpg1,
    },
    NetTestCase {
        name: "B_to_AAA",
        listener: AgentName::Dpg1Dpg1Dpg1,
        connector: AgentName::Dpg2,
    },
    NetTestCase {
        name: "AA_to_AB",
        listener: AgentName::Dpg1Dpg2,
        connector: AgentName::Dpg1Dpg1,
    },
    NetTestCase {
        name: "AAA_to_AAB",
        listener: AgentName::Dpg1Dpg1Dpg2,
        connector: AgentName::Dpg1Dpg1Dpg1,
    },
    NetTestCase {
        name: "AB_to_B",
        listener: AgentName::Dpg2,
        connector: AgentName::Dpg1Dpg2,
    },
    // Non-PIE tree: NP listens, A connects (cross-type boundary).
    NetTestCase {
        name: "dpg1_dng_to_dpg1",
        listener: AgentName::Dpg1Dng,
        connector: AgentName::Dpg1,
    },
    // PIE listens, non-PIE child connects.
    NetTestCase {
        name: "dpg1_to_dpg1_dng_dpg",
        listener: AgentName::Dpg1,
        connector: AgentName::Dpg1DngDpg,
    },
    // Non-PIE child listens, PIE from other subtree connects.
    // (Was previously 2 entries — one at depth-3, one at depth-5;
    // collapsed since the worker-host audit found grandparent
    // independence makes depth-5 redundant with depth-3.)
    NetTestCase {
        name: "dpg1_dng_dpg_to_dpg2",
        listener: AgentName::Dpg1DngDpg,
        connector: AgentName::Dpg2,
    },
];

// ═══════════════════════════════════════════════════════════════════
// NET ADDRESS MATRIX — cross-worker TCP with different connect addresses
// ═══════════════════════════════════════════════════════════════════
//
// The VS Code failure showed that the connect address matters:
// - 127.0.0.1 is standard loopback
// - 0.0.0.0 connects to INADDR_ANY (Linux treats as loopback)
//
// Both addresses must work on native Linux (gold standard) AND litebox.
// 10.0.0.2 is the litebox guest virtual IP — only tested on litebox
// (it doesn't exist on native containers which use Docker bridge IPs).

const CONNECT_ADDRS: &[&str] = &["127.0.0.1", "0.0.0.0"];

/// Historical litebox-only address — kept for documentation.
/// The matrix now discovers the self-IP dynamically via `hostname -I`.
#[allow(dead_code)]
const LITEBOX_ADDRS: &[&str] = &["10.0.0.2"];

/// Cross-worker pairs to test with address variants.
/// Each pair is tested with all `CONNECT_ADDRS` in both directions.
const NET_ADDR_PAIRS: &[(AgentName, AgentName)] = &[
    (AgentName::Dpg1, AgentName::Dpg1),
    (AgentName::Dpg1Dpg1, AgentName::Dpg1Dpg1),
    (AgentName::Dpg1, AgentName::Dpg1Dpg1),
    (AgentName::Dpg1, AgentName::Dpg2),
    (AgentName::Dpg1Dpg1Dpg1, AgentName::Dpg1Dng),
    (AgentName::Dpg1Dng, AgentName::Dpg1DngDpg),
    (AgentName::Dpg1Dng, AgentName::Dpg2),
    (AgentName::Dpg1Dng, AgentName::Dpg1),
    (AgentName::Dpg1, AgentName::Dpg1Dng),
];

// ═══════════════════════════════════════════════════════════════════
// UNIX SOCKET ADDRESS MATRIX — cross-worker Unix sockets across topology
// ═══════════════════════════════════════════════════════════════════
//
// Tests Unix domain sockets across the same topology pairs as TCP,
// ensuring cross-worker Unix sockets work at every depth.

// ═══════════════════════════════════════════════════════════════════
// EXEC & ENV
// ═══════════════════════════════════════════════════════════════════

// Long-lived agents the EXEC fan-out covers. Each entry is a parent
// process the test runs on; the test then exec()s the binary leg
// under test. Including all 5 binary-type parents ensures we
// exercise the parent-side syscall instrumentation / vDSO / fd-bridge
// paths for every leg, not just PIE-glibc and non-PIE-glibc.
const EXEC_AGENTS: &[AgentName] = &[
    AgentName::Dpg1,         // PIE-glibc
    AgentName::Dpg1Dpg1,     // PIE-glibc, depth-2
    AgentName::Dpg1Dpg1Dpg1, // PIE-glibc, depth-3
    AgentName::Dpg1Dng,      // non-PIE-glibc parent (the "node" form)
    AgentName::Dpg1DngDpg,   // PIE child of non-PIE — round-trip
    AgentName::Dpg1DngDng,   // non-PIE → non-PIE (bash recursion in VS Code)
    AgentName::Dpg1DngSpm,   // non-PIE → static-PIE-musl (bash → cli in VS Code)
    AgentName::Dpg1Spg,      // static-PIE-glibc parent
    AgentName::Dpg1Spm,      // static-PIE-musl parent (the "cli" form)
    AgentName::Dpg1SpmDng,   // static-PIE-musl → non-PIE (cli → node, VS Code's signature)
    AgentName::Dpg1Snm,      // non-PIE-static-musl parent
];

// ═══════════════════════════════════════════════════════════════════
// UNIX SOCKETS
// ═══════════════════════════════════════════════════════════════════

/// Unix socket test pattern.
#[derive(Debug, Clone, Copy)]
enum UnixPattern {
    /// Agent listens and connects to itself.
    InProcess,
    /// Agent listens, forks unix-echo-client child to connect.
    ServerForkClient,
    /// Agent starts background unix-echo-server, then connects to it.
    BackgroundServerConnect,
    /// Listener agent listens, separate connector agent connects.
    CrossAgent,
}

/// Descriptor for one unix socket test case.
struct UnixTestCase {
    name: &'static str,
    pattern: UnixPattern,
    /// Primary agent (listener for InProcess/ServerForkClient/CrossAgent,
    /// agent for `BackgroundServerConnect`).
    agent: AgentName,
    /// Connector agent for `CrossAgent` pattern.
    peer: Option<AgentName>,
}

fn unix_test_cases() -> Vec<UnixTestCase> {
    vec![
        UnixTestCase {
            name: "in_process.A",
            pattern: UnixPattern::InProcess,
            agent: AgentName::Dpg1,
            peer: None,
        },
        UnixTestCase {
            name: "in_process.AA",
            pattern: UnixPattern::InProcess,
            agent: AgentName::Dpg1Dpg1,
            peer: None,
        },
        UnixTestCase {
            name: "server_fork.A",
            pattern: UnixPattern::ServerForkClient,
            agent: AgentName::Dpg1,
            peer: None,
        },
        UnixTestCase {
            name: "server_fork.AA",
            pattern: UnixPattern::ServerForkClient,
            agent: AgentName::Dpg1Dpg1,
            peer: None,
        },
        UnixTestCase {
            name: "bg_server.A",
            pattern: UnixPattern::BackgroundServerConnect,
            agent: AgentName::Dpg1,
            peer: None,
        },
        UnixTestCase {
            name: "bg_server.AA",
            pattern: UnixPattern::BackgroundServerConnect,
            agent: AgentName::Dpg1Dpg1,
            peer: None,
        },
        // Same-worker CrossAgent cases (all connected via Spawn chains,
        // share one worker process and one unix_addr_table).
        UnixTestCase {
            name: "sibling",
            pattern: UnixPattern::CrossAgent,
            agent: AgentName::Dpg1,
            peer: Some(AgentName::Dpg2),
        },
        UnixTestCase {
            name: "parent_to_grandchild",
            pattern: UnixPattern::CrossAgent,
            agent: AgentName::Dpg1,
            peer: Some(AgentName::Dpg1Dpg1),
        },
        UnixTestCase {
            name: "grandchild_to_parent",
            pattern: UnixPattern::CrossAgent,
            agent: AgentName::Dpg1Dpg1,
            peer: Some(AgentName::Dpg1),
        },
        UnixTestCase {
            name: "cross_subtree",
            pattern: UnixPattern::CrossAgent,
            agent: AgentName::Dpg2,
            peer: Some(AgentName::Dpg1Dpg1Dpg1),
        },
        // Cross-worker CrossAgent cases — these cross a SpawnRemote boundary
        // (different OS worker processes, separate unix_addr_table).
        // Worker boundaries: {init,A,B,AA,AB,AAA,AAB,D3} | {NP,NPC} | {D4,D5}
        UnixTestCase {
            name: "vscode_d3_d4",
            pattern: UnixPattern::CrossAgent,
            agent: AgentName::Dpg1Dpg1Dpg1,
            peer: Some(AgentName::Dpg1Dng),
        },
        UnixTestCase {
            name: "vscode_d4_d3",
            pattern: UnixPattern::CrossAgent,
            agent: AgentName::Dpg1Dng,
            peer: Some(AgentName::Dpg1Dpg1Dpg1),
        },
        UnixTestCase {
            name: "d4_to_sibling_b",
            pattern: UnixPattern::CrossAgent,
            agent: AgentName::Dpg1Dng,
            peer: Some(AgentName::Dpg2),
        },
        UnixTestCase {
            name: "d5_to_a",
            pattern: UnixPattern::CrossAgent,
            agent: AgentName::Dpg1DngDpg,
            peer: Some(AgentName::Dpg1),
        },
        UnixTestCase {
            name: "a_to_np",
            pattern: UnixPattern::CrossAgent,
            agent: AgentName::Dpg1,
            peer: Some(AgentName::Dpg1Dng),
        },
        UnixTestCase {
            name: "np_to_a",
            pattern: UnixPattern::CrossAgent,
            agent: AgentName::Dpg1Dng,
            peer: Some(AgentName::Dpg1),
        },
    ]
}

// ═══════════════════════════════════════════════════════════════════
// SYMLINKS
// ═══════════════════════════════════════════════════════════════════

const SYMLINK_TOPOLOGIES: &[Topology] = &[
    Topology::InProcess,
    Topology::ParentToChild,
    Topology::ChildToParent,
    Topology::Sibling,
    Topology::GrandchildUp,
];

// ═══════════════════════════════════════════════════════════════════
// DECLARATIVE REGISTRATION
// ═══════════════════════════════════════════════════════════════════

type MatrixFuture<'r> = Pin<Box<dyn Future<Output = super::TestOutcome> + 'r>>;
type MatrixHandles = Vec<(AgentName, AgentHandle)>;

fn matrix_test<F>(reg: &mut Registry<'_>, id: impl Into<String>, required: Vec<AgentName>, body: F)
where
    F: for<'r> FnOnce(&'r mut RunContext<'_>, MatrixHandles) -> MatrixFuture<'r> + Send + 'static,
{
    reg.test("matrix", "run_matrix", id)
        .timeout(60)
        .build(move |cx| {
            let handles = required
                .into_iter()
                .map(|agent| (agent, cx.require(agent)))
                .collect::<Vec<_>>();
            Box::new(move |run| body(run, handles))
        });
}

fn handle_for(handles: &MatrixHandles, agent: AgentName) -> &AgentHandle {
    handles
        .iter()
        .find_map(|(name, handle)| (*name == agent).then_some(handle))
        .expect("agent was not declared for matrix test")
}

#[allow(clippy::too_many_lines)]
async fn send_to(
    run: &mut RunContext<'_>,
    handles: &MatrixHandles,
    agent: AgentName,
    cmd: MatrixOp,
) -> Response {
    match cmd {
        MatrixOp::FsRead { path } => {
            send_response(
                run,
                handles,
                agent,
                &FS_READ,
                FsPathArgs { path },
                local_fs_read,
            )
            .await
        }
        MatrixOp::FsWrite { path, data } => {
            send_response(
                run,
                handles,
                agent,
                &FS_WRITE,
                FsWriteArgs { path, data },
                local_fs_write,
            )
            .await
        }
        MatrixOp::FsDelete { path } => {
            send_response(
                run,
                handles,
                agent,
                &FS_DELETE,
                FsPathArgs { path },
                local_fs_delete,
            )
            .await
        }
        MatrixOp::FsSymlink { target, link } => {
            send_response(
                run,
                handles,
                agent,
                &FS_SYMLINK,
                FsSymlinkArgs { target, link },
                local_fs_symlink,
            )
            .await
        }
        MatrixOp::FsReadlink { path } => {
            send_response(
                run,
                handles,
                agent,
                &FS_READLINK,
                FsPathArgs { path },
                local_fs_readlink,
            )
            .await
        }
        MatrixOp::FsStat { path } => {
            send_response(
                run,
                handles,
                agent,
                &FS_STAT,
                FsPathArgs { path },
                local_fs_stat,
            )
            .await
        }
        MatrixOp::NetListen {
            port,
            pre_bind_options: _,
        } => {
            send_response(
                run,
                handles,
                agent,
                &NET_LISTEN,
                NetListenArgs { port },
                local_net_listen,
            )
            .await
        }
        MatrixOp::NetUnlisten { port } => {
            send_response(
                run,
                handles,
                agent,
                &NET_UNLISTEN,
                NetListenArgs { port },
                local_net_unlisten,
            )
            .await
        }
        MatrixOp::NetConnect { addr, data } => {
            send_response(
                run,
                handles,
                agent,
                &NET_CONNECT,
                NetConnectArgs { addr, data },
                local_net_connect,
            )
            .await
        }
        MatrixOp::UnixListen { path } => {
            send_response(
                run,
                handles,
                agent,
                &UNIX_LISTEN,
                FsPathArgs { path },
                local_unix_listen,
            )
            .await
        }
        MatrixOp::UnixUnlisten { path } => {
            send_response(
                run,
                handles,
                agent,
                &UNIX_UNLISTEN,
                FsPathArgs { path },
                local_unix_unlisten,
            )
            .await
        }
        MatrixOp::UnixConnect { path, data } => {
            send_response(
                run,
                handles,
                agent,
                &UNIX_CONNECT,
                UnixConnectArgs { path, data },
                local_unix_connect,
            )
            .await
        }
        MatrixOp::Exec {
            args,
            timeout_secs,
            stdin,
            background,
            env,
        } => {
            send_response(
                run,
                handles,
                agent,
                &EXEC,
                ExecArgs {
                    args,
                    timeout_secs,
                    stdin,
                    background,
                    env,
                },
                local_exec,
            )
            .await
        }
        MatrixOp::ExecReady {
            args,
            ready_marker,
            timeout_secs,
            stdin,
            stream,
        } => {
            send_response(
                run,
                handles,
                agent,
                &EXEC_READY,
                ExecReadyArgs {
                    args,
                    ready_marker,
                    timeout_secs,
                    stdin,
                    stream,
                },
                local_exec_ready,
            )
            .await
        }
        MatrixOp::Kill { pid } => {
            send_response(run, handles, agent, &KILL, KillArgs { pid }, local_kill).await
        }
        MatrixOp::EnvGet { var } => {
            send_response(
                run,
                handles,
                agent,
                &ENV_GET,
                EnvGetArgs { var },
                local_env_get,
            )
            .await
        }
        MatrixOp::CwdGet => {
            if agent == AgentName::Init {
                local_cwd_get(()).await
            } else {
                run.send_named_typed(handle_for(handles, agent), &CWD_GET, ())
                    .await
                    .unwrap_or_else(|error| Response::Error { error })
            }
        }
    }
}

#[allow(clippy::too_many_lines)] // exhaustive registration / runner
pub(super) fn register_fs_crud(reg: &mut Registry<'_>) {
    for &topo in FS_TOPOLOGIES {
        let (source, dest) = topo.agents();
        let ts = topo.suffix();

        let required = vec![AgentName::Init, source, dest];
        matrix_test(
            reg,
            format!("F.shared.{ts}.absent"),
            required.clone(),
            move |run, handles| {
                Box::pin(async move {
                    let file = format!("/shared/matrix_{ts}.txt");
                    let _ = send_to(
                        run,
                        &handles,
                        AgentName::Init,
                        MatrixOp::FsDelete { path: file.clone() },
                    )
                    .await;
                    let resp = send_to(run, &handles, dest, MatrixOp::FsRead { path: file }).await;
                    super::TestOutcome::new(
                        dest.name(),
                        matches!(resp, Response::NotFound),
                        format!("{resp:?}"),
                    )
                })
            },
        );
        matrix_test(
            reg,
            format!("F.shared.{ts}.created"),
            required.clone(),
            move |run, handles| {
                Box::pin(async move {
                    let file = format!("/shared/matrix_{ts}.txt");
                    let data = format!("data_{ts}");
                    let _ = send_to(
                        run,
                        &handles,
                        AgentName::Init,
                        MatrixOp::FsDelete { path: file.clone() },
                    )
                    .await;
                    let _ = send_to(
                        run,
                        &handles,
                        source,
                        MatrixOp::FsWrite {
                            path: file.clone(),
                            data: data.clone(),
                        },
                    )
                    .await;
                    let resp = send_to(run, &handles, dest, MatrixOp::FsRead { path: file }).await;
                    let pass = matches!(&resp, Response::Ok { data: Some(d) } if *d == data);
                    super::TestOutcome::new(dest.name(), pass, format!("{resp:?}"))
                })
            },
        );
        matrix_test(
            reg,
            format!("F.shared.{ts}.updated"),
            required.clone(),
            move |run, handles| {
                Box::pin(async move {
                    let file = format!("/shared/matrix_{ts}.txt");
                    let updated = format!("updated_{ts}");
                    let _ = send_to(
                        run,
                        &handles,
                        AgentName::Init,
                        MatrixOp::FsDelete { path: file.clone() },
                    )
                    .await;
                    let _ = send_to(
                        run,
                        &handles,
                        source,
                        MatrixOp::FsWrite {
                            path: file.clone(),
                            data: format!("data_{ts}"),
                        },
                    )
                    .await;
                    let _ = send_to(
                        run,
                        &handles,
                        source,
                        MatrixOp::FsWrite {
                            path: file.clone(),
                            data: updated.clone(),
                        },
                    )
                    .await;
                    let resp = send_to(run, &handles, dest, MatrixOp::FsRead { path: file }).await;
                    let pass = matches!(&resp, Response::Ok { data: Some(d) } if *d == updated);
                    super::TestOutcome::new(dest.name(), pass, format!("{resp:?}"))
                })
            },
        );
        matrix_test(
            reg,
            format!("F.shared.{ts}.deleted"),
            required,
            move |run, handles| {
                Box::pin(async move {
                    let file = format!("/shared/matrix_{ts}.txt");
                    let _ = send_to(
                        run,
                        &handles,
                        AgentName::Init,
                        MatrixOp::FsDelete { path: file.clone() },
                    )
                    .await;
                    let _ = send_to(
                        run,
                        &handles,
                        source,
                        MatrixOp::FsWrite {
                            path: file.clone(),
                            data: format!("data_{ts}"),
                        },
                    )
                    .await;
                    let _ = send_to(
                        run,
                        &handles,
                        source,
                        MatrixOp::FsDelete { path: file.clone() },
                    )
                    .await;
                    let resp = send_to(run, &handles, dest, MatrixOp::FsRead { path: file }).await;
                    super::TestOutcome::new(
                        dest.name(),
                        matches!(resp, Response::NotFound),
                        format!("{resp:?}"),
                    )
                })
            },
        );
    }
}

pub(super) fn register_fs_cross_unlink(reg: &mut Registry<'_>) {
    for &topo in FS_TOPOLOGIES {
        let (source, dest) = topo.agents();
        let ts = topo.suffix();

        let required = vec![AgentName::Init, source, dest];
        matrix_test(
            reg,
            format!("F.unlink.{ts}.delete"),
            required.clone(),
            move |run, handles| {
                Box::pin(async move {
                    let file = format!("/shared/unlink_{ts}.txt");
                    let _ = send_to(
                        run,
                        &handles,
                        AgentName::Init,
                        MatrixOp::FsDelete { path: file.clone() },
                    )
                    .await;
                    let _ = send_to(
                        run,
                        &handles,
                        source,
                        MatrixOp::FsWrite {
                            path: file.clone(),
                            data: "unlink_me".into(),
                        },
                    )
                    .await;
                    let resp =
                        send_to(run, &handles, dest, MatrixOp::FsDelete { path: file }).await;
                    super::TestOutcome::new(
                        dest.name(),
                        super::ok_without_data(&resp),
                        format!("{resp:?}"),
                    )
                })
            },
        );
        matrix_test(
            reg,
            format!("F.unlink.{ts}.gone"),
            required,
            move |run, handles| {
                Box::pin(async move {
                    let file = format!("/shared/unlink_{ts}.txt");
                    let _ = send_to(
                        run,
                        &handles,
                        AgentName::Init,
                        MatrixOp::FsDelete { path: file.clone() },
                    )
                    .await;
                    let _ = send_to(
                        run,
                        &handles,
                        source,
                        MatrixOp::FsWrite {
                            path: file.clone(),
                            data: "unlink_me".into(),
                        },
                    )
                    .await;
                    let _ = send_to(
                        run,
                        &handles,
                        dest,
                        MatrixOp::FsDelete { path: file.clone() },
                    )
                    .await;
                    let resp =
                        send_to(run, &handles, source, MatrixOp::FsRead { path: file }).await;
                    super::TestOutcome::new(
                        source.name(),
                        matches!(resp, Response::NotFound),
                        format!("{resp:?}"),
                    )
                })
            },
        );
    }
}

pub(super) fn register_tmp_isolation(reg: &mut Registry<'_>) {
    for &topo in FS_TOPOLOGIES {
        let (writer, reader) = topo.agents();
        let ts = topo.suffix();

        if writer == reader {
            continue;
        }
        matrix_test(
            reg,
            format!("F.tmp.{ts}.isolation"),
            vec![writer, reader],
            move |run, handles| {
                Box::pin(async move {
                    let file = format!("/tmp/matrix_iso_{ts}.txt");
                    let _ = send_to(
                        run,
                        &handles,
                        writer,
                        MatrixOp::FsWrite {
                            path: file.clone(),
                            data: "tmp_test".into(),
                        },
                    )
                    .await;
                    let resp =
                        send_to(run, &handles, reader, MatrixOp::FsRead { path: file }).await;
                    let is_isolated = matches!(resp, Response::NotFound);
                    super::TestOutcome::new(
                        reader.name(),
                        true,
                        format!("isolated={is_isolated}: {resp:?}"),
                    )
                })
            },
        );
    }
}

pub(super) fn register_host_file(reg: &mut Registry<'_>) {
    for agent in [AgentName::Init, AgentName::Dpg1, AgentName::Dpg1Dpg1] {
        matrix_test(
            reg,
            format!("F.host.{agent}"),
            vec![agent],
            move |run, handles| {
                Box::pin(async move {
                    let resp = send_to(
                        run,
                        &handles,
                        agent,
                        MatrixOp::FsRead {
                            path: "/shared/host_wrote.txt".into(),
                        },
                    )
                    .await;
                    // /shared/host_wrote.txt is provisioned by the rootfs Dockerfile
                    // (litebox_tool_executor/rootfs/Dockerfile, content "from_host").
                    // NotFound here is a real failure (broken rootfs / wrong image),
                    // not a skippable condition.
                    let pass = matches!(&resp, Response::Ok { data: Some(d) } if d == "from_host");
                    super::TestOutcome::new(agent.name(), pass, format!("{resp:?}"))
                })
            },
        );
    }
}

#[allow(clippy::too_many_lines)]
pub(super) fn register_net_tests(reg: &mut Registry<'_>) {
    let mut port = 10_001u16;
    for tc in NET_TESTS {
        let p = port;
        port += 1;
        let (name, listener, connector) = (tc.name, tc.listener, tc.connector);

        matrix_test(
            reg,
            format!("N.{name}.listen"),
            vec![listener],
            move |run, handles| {
                Box::pin(async move {
                    let resp = send_to(
                        run,
                        &handles,
                        listener,
                        MatrixOp::NetListen {
                            port: p,
                            pre_bind_options: vec![],
                        },
                    )
                    .await;
                    let pass = super::expect_listening_port(&resp, p).is_ok();
                    let _ =
                        send_to(run, &handles, listener, MatrixOp::NetUnlisten { port: p }).await;
                    super::TestOutcome::new(listener.name(), pass, format!("{resp:?}"))
                })
            },
        );
        let test_data = format!("net_{name}");
        matrix_test(
            reg,
            format!("N.{name}.connect"),
            vec![listener, connector],
            move |run, handles| {
                Box::pin(async move {
                    let resp = send_to(
                        run,
                        &handles,
                        listener,
                        MatrixOp::NetListen {
                            port: p,
                            pre_bind_options: vec![],
                        },
                    )
                    .await;
                    if let Err(e) = super::expect_listening_port(&resp, p) {
                        return super::TestOutcome::new(
                            connector.name(),
                            false,
                            format!("listen failed: {e}; resp={resp:?}"),
                        );
                    }
                    let resp = send_to(
                        run,
                        &handles,
                        connector,
                        MatrixOp::NetConnect {
                            addr: format!("127.0.0.1:{p}"),
                            data: test_data.clone(),
                        },
                    )
                    .await;
                    let pass = matches!(&resp, Response::Connected { echo } if *echo == test_data);
                    let _ =
                        send_to(run, &handles, listener, MatrixOp::NetUnlisten { port: p }).await;
                    super::TestOutcome::new(connector.name(), pass, format!("{resp:?}"))
                })
            },
        );
        matrix_test(
            reg,
            format!("N.{name}.unlisten"),
            vec![listener],
            move |run, handles| {
                Box::pin(async move {
                    let _ = send_to(
                        run,
                        &handles,
                        listener,
                        MatrixOp::NetListen {
                            port: p,
                            pre_bind_options: vec![],
                        },
                    )
                    .await;
                    let resp =
                        send_to(run, &handles, listener, MatrixOp::NetUnlisten { port: p }).await;
                    super::TestOutcome::new(
                        listener.name(),
                        super::ok_without_data(&resp),
                        format!("{resp:?}"),
                    )
                })
            },
        );
    }
}

#[allow(clippy::too_many_lines)]
pub(super) fn register_net_addr_tests(reg: &mut Registry<'_>) {
    let mut port = 11_001u16;
    for &(agent_a, agent_b) in NET_ADDR_PAIRS {
        for &addr in CONNECT_ADDRS {
            let p = port;
            port += 1;

            let test_data = format!("na_{agent_a}_{agent_b}_{addr}");
            matrix_test(
                reg,
                format!("NA.{agent_a}_to_{agent_b}.{addr}"),
                vec![agent_a, agent_b],
                move |run, handles| {
                    Box::pin(async move {
                        let resp = send_to(
                            run,
                            &handles,
                            agent_a,
                            MatrixOp::NetListen {
                                port: p,
                                pre_bind_options: vec![],
                            },
                        )
                        .await;
                        if let Err(e) = super::expect_listening_port(&resp, p) {
                            return super::TestOutcome::new(
                                agent_b.name(),
                                false,
                                format!("listen failed: {e}; resp={resp:?}"),
                            );
                        }
                        let resp = send_to(
                            run,
                            &handles,
                            agent_b,
                            MatrixOp::NetConnect {
                                addr: format!("{addr}:{p}"),
                                data: test_data.clone(),
                            },
                        )
                        .await;
                        let pass =
                            matches!(&resp, Response::Connected { echo } if *echo == test_data);
                        let _ = send_to(run, &handles, agent_a, MatrixOp::NetUnlisten { port: p })
                            .await;
                        super::TestOutcome::new(agent_b.name(), pass, format!("{resp:?}"))
                    })
                },
            );
        }
        let p = port;
        port += 1;

        let test_data = format!("na_{agent_a}_{agent_b}_self_ip");
        matrix_test(
            reg,
            format!("NA.{agent_a}_to_{agent_b}.self_ip"),
            vec![agent_a, agent_b],
            move |run, handles| {
                Box::pin(async move {
                    let self_ip = tokio::process::Command::new("hostname")
                        .arg("-I")
                        .output()
                        .await
                        .ok()
                        .and_then(|o| String::from_utf8(o.stdout).ok())
                        .and_then(|s| {
                            s.split_whitespace()
                                .find(|ip| *ip != "127.0.0.1" && !ip.contains(':'))
                                .map(String::from)
                        });
                    let Some(addr) = self_ip else {
                        return super::TestOutcome::new(
                            agent_b.name(),
                            false,
                            "self_ip not discoverable via `hostname -I`; \
                             test container is misconfigured (no non-loopback IPv4)",
                        );
                    };
                    let resp = send_to(
                        run,
                        &handles,
                        agent_a,
                        MatrixOp::NetListen {
                            port: p,
                            pre_bind_options: vec![],
                        },
                    )
                    .await;
                    if let Err(e) = super::expect_listening_port(&resp, p) {
                        return super::TestOutcome::new(
                            agent_b.name(),
                            false,
                            format!("listen failed: {e}; resp={resp:?}"),
                        );
                    }
                    let resp = send_to(
                        run,
                        &handles,
                        agent_b,
                        MatrixOp::NetConnect {
                            addr: format!("{addr}:{p}"),
                            data: test_data.clone(),
                        },
                    )
                    .await;
                    let pass = matches!(&resp, Response::Connected { echo } if *echo == test_data);
                    let _ =
                        send_to(run, &handles, agent_a, MatrixOp::NetUnlisten { port: p }).await;
                    super::TestOutcome::new(agent_b.name(), pass, format!("{resp:?}"))
                })
            },
        );
    }
}

pub(super) fn register_unix_addr_tests(reg: &mut Registry<'_>) {
    for (i, &(agent_a, agent_b)) in NET_ADDR_PAIRS.iter().enumerate() {
        let i = u32::try_from(i).expect("NET_ADDR_PAIRS too large");

        let test_data = format!("ua_{agent_a}_{agent_b}");
        matrix_test(
            reg,
            format!("UA.{agent_a}_to_{agent_b}"),
            vec![agent_a, agent_b],
            move |run, handles| {
                Box::pin(async move {
                    let sock_path = format!("/tmp/ua-{i}.sock");
                    let resp = send_to(
                        run,
                        &handles,
                        agent_a,
                        MatrixOp::UnixListen {
                            path: sock_path.clone(),
                        },
                    )
                    .await;
                    if let Err(e) = super::expect_unix_listening_path(&resp, &sock_path) {
                        return super::TestOutcome::new(
                            agent_b.name(),
                            false,
                            format!("listen failed: {e}; resp={resp:?}"),
                        );
                    }
                    let resp = send_to(
                        run,
                        &handles,
                        agent_b,
                        MatrixOp::UnixConnect {
                            path: sock_path.clone(),
                            data: test_data.clone(),
                        },
                    )
                    .await;
                    let pass = matches!(&resp, Response::Connected { echo } if *echo == test_data);
                    let _ = send_to(
                        run,
                        &handles,
                        agent_a,
                        MatrixOp::UnixUnlisten { path: sock_path },
                    )
                    .await;
                    super::TestOutcome::new(agent_b.name(), pass, format!("{resp:?}"))
                })
            },
        );
    }
}

pub(super) fn register_exec_tests(reg: &mut Registry<'_>) {
    for &agent in EXEC_AGENTS {
        for &bt in crate::BinaryType::ALL {
            let bt_label = bt.label();
            matrix_test(
                reg,
                format!("X.echo.{bt_label}.{agent}"),
                vec![agent],
                move |run, handles| {
                    Box::pin(async move {
                        let self_exe = run.self_exe().to_string();
                        let target = crate::binary_path(bt, &self_exe);
                        let resp =
                            send_to(run, &handles, agent, exec(vec![target, "echo-test".into()]))
                                .await;
                        let pass = matches!(
                            &resp,
                            Response::ExecResult { exit_code: 0, stdout, .. }
                                if stdout.contains("ECHO_TEST_OK")
                        );
                        super::TestOutcome::new(agent.name(), pass, format!("{resp:?}"))
                    })
                },
            );
        }
    }
    for &(agent, code) in &[(AgentName::Dpg1, 42i32), (AgentName::Dpg1Dpg1Dpg1, 7i32)] {
        for &bt in crate::BinaryType::ALL {
            let bt_label = bt.label();
            matrix_test(
                reg,
                format!("X.exit_code.{bt_label}.{agent}.{code}"),
                vec![agent],
                move |run, handles| {
                    Box::pin(async move {
                        let self_exe = run.self_exe().to_string();
                        let target = crate::binary_path(bt, &self_exe);
                        let resp = send_to(
                            run,
                            &handles,
                            agent,
                            exec(vec![target, "exit-with".into(), code.to_string()]),
                        )
                        .await;
                        let pass = matches!(&resp, Response::ExecResult { exit_code, .. } if *exit_code == code);
                        super::TestOutcome::new(agent.name(), pass, format!("{resp:?}"))
                    })
                },
            );
        }
    }
}

pub(super) fn register_env_tests(reg: &mut Registry<'_>) {
    for &agent in EXEC_AGENTS {
        for var in ["HOME", "PATH"] {
            matrix_test(
                reg,
                format!("E.{var}.{agent}"),
                vec![agent],
                move |run, handles| {
                    Box::pin(async move {
                        let resp =
                            send_to(run, &handles, agent, MatrixOp::EnvGet { var: var.into() })
                                .await;
                        let pass = matches!(&resp, Response::Ok { data: Some(d) } if !d.is_empty() && d != "NOT_SET");
                        super::TestOutcome::new(agent.name(), pass, format!("{resp:?}"))
                    })
                },
            );
        }
        matrix_test(
            reg,
            format!("E.CWD.{agent}"),
            vec![agent],
            move |run, handles| {
                Box::pin(async move {
                    let resp = send_to(run, &handles, agent, MatrixOp::CwdGet).await;
                    super::TestOutcome::new(
                        agent.name(),
                        matches!(&resp, Response::Ok { data: Some(d) } if d == "/"),
                        format!("{resp:?}"),
                    )
                })
            },
        );
    }
}

#[allow(clippy::too_many_lines)] // exhaustive registration / runner
pub(super) fn register_symlink_basic(reg: &mut Registry<'_>) {
    for &topo in SYMLINK_TOPOLOGIES {
        let (source, dest) = topo.agents();
        let ts = topo.suffix();
        let required = vec![AgentName::Init, source, dest];
        matrix_test(
            reg,
            format!("S.basic.{ts}.create"),
            required.clone(),
            move |run, handles| {
                Box::pin(async move {
                    let file = format!("/shared/sm_{ts}_file");
                    let link = format!("/shared/sm_{ts}_link");
                    let _ = send_to(
                        run,
                        &handles,
                        AgentName::Init,
                        MatrixOp::FsDelete { path: link.clone() },
                    )
                    .await;
                    let _ = send_to(
                        run,
                        &handles,
                        AgentName::Init,
                        MatrixOp::FsDelete { path: file.clone() },
                    )
                    .await;
                    let _ = send_to(
                        run,
                        &handles,
                        source,
                        MatrixOp::FsWrite {
                            path: file.clone(),
                            data: format!("symdata_{ts}"),
                        },
                    )
                    .await;
                    let resp = send_to(
                        run,
                        &handles,
                        source,
                        MatrixOp::FsSymlink { target: file, link },
                    )
                    .await;
                    super::TestOutcome::new(
                        source.name(),
                        super::ok_without_data(&resp),
                        format!("{resp:?}"),
                    )
                })
            },
        );
        matrix_test(
            reg,
            format!("S.basic.{ts}.readlink"),
            required.clone(),
            move |run, handles| {
                Box::pin(async move {
                    let file = format!("/shared/sm_{ts}_file");
                    let link = format!("/shared/sm_{ts}_link");
                    let _ = send_to(
                        run,
                        &handles,
                        AgentName::Init,
                        MatrixOp::FsDelete { path: link.clone() },
                    )
                    .await;
                    let _ = send_to(
                        run,
                        &handles,
                        AgentName::Init,
                        MatrixOp::FsDelete { path: file.clone() },
                    )
                    .await;
                    let _ = send_to(
                        run,
                        &handles,
                        source,
                        MatrixOp::FsWrite {
                            path: file.clone(),
                            data: format!("symdata_{ts}"),
                        },
                    )
                    .await;
                    let _ = send_to(
                        run,
                        &handles,
                        source,
                        MatrixOp::FsSymlink {
                            target: file.clone(),
                            link: link.clone(),
                        },
                    )
                    .await;
                    let resp =
                        send_to(run, &handles, source, MatrixOp::FsReadlink { path: link }).await;
                    let pass = matches!(&resp, Response::Ok { data: Some(d) } if *d == file);
                    super::TestOutcome::new(source.name(), pass, format!("{resp:?}"))
                })
            },
        );
        matrix_test(
            reg,
            format!("S.basic.{ts}.read_through"),
            required.clone(),
            move |run, handles| {
                Box::pin(async move {
                    let file = format!("/shared/sm_{ts}_file");
                    let link = format!("/shared/sm_{ts}_link");
                    let data = format!("symdata_{ts}");
                    let _ = send_to(
                        run,
                        &handles,
                        AgentName::Init,
                        MatrixOp::FsDelete { path: link.clone() },
                    )
                    .await;
                    let _ = send_to(
                        run,
                        &handles,
                        AgentName::Init,
                        MatrixOp::FsDelete { path: file.clone() },
                    )
                    .await;
                    let _ = send_to(
                        run,
                        &handles,
                        source,
                        MatrixOp::FsWrite {
                            path: file.clone(),
                            data: data.clone(),
                        },
                    )
                    .await;
                    let _ = send_to(
                        run,
                        &handles,
                        source,
                        MatrixOp::FsSymlink {
                            target: file,
                            link: link.clone(),
                        },
                    )
                    .await;
                    let resp = send_to(run, &handles, dest, MatrixOp::FsRead { path: link }).await;
                    let pass = matches!(&resp, Response::Ok { data: Some(d) } if *d == data);
                    super::TestOutcome::new(dest.name(), pass, format!("{resp:?}"))
                })
            },
        );
        matrix_test(
            reg,
            format!("S.basic.{ts}.stat_type"),
            required,
            move |run, handles| {
                Box::pin(async move {
                    let file = format!("/shared/sm_{ts}_file");
                    let link = format!("/shared/sm_{ts}_link");
                    let _ = send_to(
                        run,
                        &handles,
                        AgentName::Init,
                        MatrixOp::FsDelete { path: link.clone() },
                    )
                    .await;
                    let _ = send_to(
                        run,
                        &handles,
                        AgentName::Init,
                        MatrixOp::FsDelete { path: file.clone() },
                    )
                    .await;
                    let _ = send_to(
                        run,
                        &handles,
                        source,
                        MatrixOp::FsWrite {
                            path: file.clone(),
                            data: format!("symdata_{ts}"),
                        },
                    )
                    .await;
                    let _ = send_to(
                        run,
                        &handles,
                        source,
                        MatrixOp::FsSymlink {
                            target: file,
                            link: link.clone(),
                        },
                    )
                    .await;
                    let resp = send_to(run, &handles, dest, MatrixOp::FsStat { path: link }).await;
                    let pass = matches!(&resp, Response::Ok { data: Some(d) } if d == "symlink");
                    super::TestOutcome::new(dest.name(), pass, format!("{resp:?}"))
                })
            },
        );
    }
}

#[allow(clippy::too_many_lines)] // exhaustive registration / runner
pub(super) fn register_symlink_variants(reg: &mut Registry<'_>) {
    let agent = AgentName::Dpg1;
    matrix_test(
        reg,
        "S.dir.read_through",
        vec![agent],
        move |run, handles| {
            Box::pin(async move {
                let _ = send_to(
                    run,
                    &handles,
                    agent,
                    exec(vec![
                        "rm".into(),
                        "-rf".into(),
                        "/shared/sv_dir".into(),
                        "/shared/sv_dirlink".into(),
                    ]),
                )
                .await;
                let _ = send_to(
                    run,
                    &handles,
                    agent,
                    exec(vec![
                        "bash".into(),
                        "-c".into(),
                        "mkdir -p /shared/sv_dir && echo DIR_CONTENT > /shared/sv_dir/inside.txt"
                            .into(),
                    ]),
                )
                .await;
                let _ = send_to(
                    run,
                    &handles,
                    agent,
                    MatrixOp::FsSymlink {
                        target: "/shared/sv_dir".into(),
                        link: "/shared/sv_dirlink".into(),
                    },
                )
                .await;
                let resp = send_to(
                    run,
                    &handles,
                    agent,
                    MatrixOp::FsRead {
                        path: "/shared/sv_dirlink/inside.txt".into(),
                    },
                )
                .await;
                let pass =
                    matches!(&resp, Response::Ok { data: Some(d) } if d.trim() == "DIR_CONTENT");
                super::TestOutcome::new(agent.name(), pass, format!("{resp:?}"))
            })
        },
    );
    matrix_test(
        reg,
        "S.dangling.readlink",
        vec![AgentName::Init, agent],
        move |run, handles| {
            Box::pin(async move {
                let _ = send_to(
                    run,
                    &handles,
                    AgentName::Init,
                    MatrixOp::FsDelete {
                        path: "/shared/sv_dangling".into(),
                    },
                )
                .await;
                let _ = send_to(
                    run,
                    &handles,
                    agent,
                    MatrixOp::FsSymlink {
                        target: "/shared/nonexistent_target".into(),
                        link: "/shared/sv_dangling".into(),
                    },
                )
                .await;
                let resp = send_to(
                    run,
                    &handles,
                    agent,
                    MatrixOp::FsReadlink {
                        path: "/shared/sv_dangling".into(),
                    },
                )
                .await;
                let pass = matches!(&resp, Response::Ok { data: Some(d) } if d == "/shared/nonexistent_target");
                super::TestOutcome::new(agent.name(), pass, format!("{resp:?}"))
            })
        },
    );
    matrix_test(
        reg,
        "S.dangling.read_fails",
        vec![AgentName::Init, agent],
        move |run, handles| {
            Box::pin(async move {
                let _ = send_to(
                    run,
                    &handles,
                    AgentName::Init,
                    MatrixOp::FsDelete {
                        path: "/shared/sv_dangling".into(),
                    },
                )
                .await;
                let _ = send_to(
                    run,
                    &handles,
                    agent,
                    MatrixOp::FsSymlink {
                        target: "/shared/nonexistent_target".into(),
                        link: "/shared/sv_dangling".into(),
                    },
                )
                .await;
                let resp = send_to(
                    run,
                    &handles,
                    agent,
                    MatrixOp::FsRead {
                        path: "/shared/sv_dangling".into(),
                    },
                )
                .await;
                super::TestOutcome::new(
                    agent.name(),
                    matches!(&resp, Response::Error { .. } | Response::NotFound),
                    format!("{resp:?}"),
                )
            })
        },
    );
    matrix_test(
        reg,
        "S.nested.read_through",
        vec![AgentName::Init, agent],
        move |run, handles| {
            Box::pin(async move {
                for name in ["sv_nested_link1", "sv_nested_link2", "sv_nested_file"] {
                    let _ = send_to(
                        run,
                        &handles,
                        AgentName::Init,
                        MatrixOp::FsDelete {
                            path: format!("/shared/{name}"),
                        },
                    )
                    .await;
                }
                let _ = send_to(
                    run,
                    &handles,
                    agent,
                    MatrixOp::FsWrite {
                        path: "/shared/sv_nested_file".into(),
                        data: "NESTED_DATA".into(),
                    },
                )
                .await;
                let _ = send_to(
                    run,
                    &handles,
                    agent,
                    MatrixOp::FsSymlink {
                        target: "/shared/sv_nested_file".into(),
                        link: "/shared/sv_nested_link2".into(),
                    },
                )
                .await;
                let _ = send_to(
                    run,
                    &handles,
                    agent,
                    MatrixOp::FsSymlink {
                        target: "/shared/sv_nested_link2".into(),
                        link: "/shared/sv_nested_link1".into(),
                    },
                )
                .await;
                let resp = send_to(
                    run,
                    &handles,
                    agent,
                    MatrixOp::FsRead {
                        path: "/shared/sv_nested_link1".into(),
                    },
                )
                .await;
                let pass = matches!(&resp, Response::Ok { data: Some(d) } if d == "NESTED_DATA");
                super::TestOutcome::new(agent.name(), pass, format!("{resp:?}"))
            })
        },
    );
    matrix_test(
        reg,
        "S.relative.read_through",
        vec![AgentName::Init, agent],
        move |run, handles| {
            Box::pin(async move {
                for name in ["sv_rel_file", "sv_rel_link"] {
                    let _ = send_to(
                        run,
                        &handles,
                        AgentName::Init,
                        MatrixOp::FsDelete {
                            path: format!("/shared/{name}"),
                        },
                    )
                    .await;
                }
                let _ = send_to(
                    run,
                    &handles,
                    agent,
                    MatrixOp::FsWrite {
                        path: "/shared/sv_rel_file".into(),
                        data: "REL_DATA".into(),
                    },
                )
                .await;
                let _ = send_to(
                    run,
                    &handles,
                    agent,
                    MatrixOp::FsSymlink {
                        target: "sv_rel_file".into(),
                        link: "/shared/sv_rel_link".into(),
                    },
                )
                .await;
                let resp = send_to(
                    run,
                    &handles,
                    agent,
                    MatrixOp::FsRead {
                        path: "/shared/sv_rel_link".into(),
                    },
                )
                .await;
                let pass = matches!(&resp, Response::Ok { data: Some(d) } if d == "REL_DATA");
                super::TestOutcome::new(agent.name(), pass, format!("{resp:?}"))
            })
        },
    );
}

#[allow(clippy::too_many_lines)] // exhaustive registration / runner
pub(super) fn register_unix_tests(reg: &mut Registry<'_>) {
    for tc in unix_test_cases() {
        let sock = format!("/tmp/um_{}.sock", tc.name.replace('.', "_"));
        let agent = tc.agent;
        let name = tc.name;
        match tc.pattern {
            UnixPattern::InProcess => {
                let sock_listen = sock.clone();
                matrix_test(
                    reg,
                    format!("U.{name}.listen"),
                    vec![agent],
                    move |run, handles| {
                        Box::pin(async move {
                            let resp = send_to(
                                run,
                                &handles,
                                agent,
                                MatrixOp::UnixListen {
                                    path: sock_listen.clone(),
                                },
                            )
                            .await;
                            let pass =
                                super::expect_unix_listening_path(&resp, &sock_listen).is_ok();
                            let _ = send_to(
                                run,
                                &handles,
                                agent,
                                MatrixOp::UnixUnlisten { path: sock_listen },
                            )
                            .await;
                            super::TestOutcome::new(agent.name(), pass, format!("{resp:?}"))
                        })
                    },
                );
                matrix_test(
                    reg,
                    format!("U.{name}.connect"),
                    vec![agent],
                    move |run, handles| {
                        Box::pin(async move {
                            let resp = send_to(
                                run,
                                &handles,
                                agent,
                                MatrixOp::UnixListen { path: sock.clone() },
                            )
                            .await;
                            if let Err(e) = super::expect_unix_listening_path(&resp, &sock) {
                                return super::TestOutcome::new(
                                    agent.name(),
                                    false,
                                    format!("listen failed: {e}; resp={resp:?}"),
                                );
                            }
                            let data = format!("unix_{name}");
                            let resp = send_to(
                                run,
                                &handles,
                                agent,
                                MatrixOp::UnixConnect {
                                    path: sock.clone(),
                                    data: data.clone(),
                                },
                            )
                            .await;
                            let pass =
                                matches!(&resp, Response::Connected { echo } if *echo == data);
                            let _ = send_to(
                                run,
                                &handles,
                                agent,
                                MatrixOp::UnixUnlisten { path: sock },
                            )
                            .await;
                            super::TestOutcome::new(agent.name(), pass, format!("{resp:?}"))
                        })
                    },
                );
            }
            UnixPattern::ServerForkClient => {
                let sock_listen = sock.clone();
                matrix_test(
                    reg,
                    format!("U.{name}.listen"),
                    vec![agent],
                    move |run, handles| {
                        Box::pin(async move {
                            let resp = send_to(
                                run,
                                &handles,
                                agent,
                                MatrixOp::UnixListen {
                                    path: sock_listen.clone(),
                                },
                            )
                            .await;
                            let pass =
                                super::expect_unix_listening_path(&resp, &sock_listen).is_ok();
                            let _ = send_to(
                                run,
                                &handles,
                                agent,
                                MatrixOp::UnixUnlisten { path: sock_listen },
                            )
                            .await;
                            super::TestOutcome::new(agent.name(), pass, format!("{resp:?}"))
                        })
                    },
                );
                for &bt in crate::BinaryType::ALL {
                    let bt_label = bt.label();
                    let sock = format!("/tmp/um_{}_{}.sock", name.replace('.', "_"), bt_label);
                    matrix_test(
                        reg,
                        format!("U.{name}.{bt_label}.child_connect"),
                        vec![agent],
                        move |run, handles| {
                            Box::pin(async move {
                                let self_exe = run.self_exe().to_string();
                                let target = crate::binary_path(bt, &self_exe);
                                let resp = send_to(
                                    run,
                                    &handles,
                                    agent,
                                    MatrixOp::UnixListen { path: sock.clone() },
                                )
                                .await;
                                if let Err(e) = super::expect_unix_listening_path(&resp, &sock) {
                                    return super::TestOutcome::new(
                                        agent.name(),
                                        false,
                                        format!("listen failed: {e}; resp={resp:?}"),
                                    );
                                }
                                let data = format!("unix_{name}");
                                let resp = send_to(
                                    run,
                                    &handles,
                                    agent,
                                    exec(vec![
                                        target,
                                        "unix-echo-client".into(),
                                        sock.clone(),
                                        data.clone(),
                                    ]),
                                )
                                .await;
                                let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains(&data));
                                let _ = send_to(
                                    run,
                                    &handles,
                                    agent,
                                    MatrixOp::UnixUnlisten { path: sock },
                                )
                                .await;
                                super::TestOutcome::new(agent.name(), pass, format!("{resp:?}"))
                            })
                        },
                    );
                }
            }
            UnixPattern::BackgroundServerConnect => {
                for &bt in crate::BinaryType::ALL {
                    let bt_label = bt.label();
                    let sock_start =
                        format!("/tmp/um_{}_{}_start.sock", name.replace('.', "_"), bt_label);
                    matrix_test(
                        reg,
                        format!("U.{name}.{bt_label}.server_start"),
                        vec![agent],
                        move |run, handles| {
                            Box::pin(async move {
                                let self_exe = run.self_exe().to_string();
                                let target = crate::binary_path(bt, &self_exe);
                                let resp = send_to(
                                    run,
                                    &handles,
                                    agent,
                                    MatrixOp::Exec {
                                        args: vec![
                                            target,
                                            "unix-echo-server".into(),
                                            sock_start.clone(),
                                        ],
                                        timeout_secs: None,
                                        stdin: None,
                                        background: true,
                                        env: vec![],
                                    },
                                )
                                .await;
                                let pid = match &resp {
                                    Response::Background { pid } => Some(*pid),
                                    _ => None,
                                };
                                let pass = pid.is_some();
                                if let Some(pid) = pid {
                                    let _ =
                                        send_to(run, &handles, agent, MatrixOp::Kill { pid }).await;
                                }
                                let _ = send_to(
                                    run,
                                    &handles,
                                    agent,
                                    MatrixOp::UnixUnlisten { path: sock_start },
                                )
                                .await;
                                super::TestOutcome::new(agent.name(), pass, format!("{resp:?}"))
                            })
                        },
                    );
                }
                for &bt in crate::BinaryType::ALL {
                    let bt_label = bt.label();
                    let sock = format!(
                        "/tmp/um_{}_{}_connect.sock",
                        name.replace('.', "_"),
                        bt_label
                    );
                    matrix_test(
                        reg,
                        format!("U.{name}.{bt_label}.connect"),
                        vec![agent],
                        move |run, handles| {
                            Box::pin(async move {
                                let self_exe = run.self_exe().to_string();
                                let target = crate::binary_path(bt, &self_exe);
                                let resp = send_to(
                                    run,
                                    &handles,
                                    agent,
                                    MatrixOp::ExecReady {
                                        args: vec![target, "unix-echo-server".into(), sock.clone()],
                                        ready_marker: "LISTENING".into(),
                                        timeout_secs: Some(10),
                                        stdin: None,
                                        stream: "stdout".into(),
                                    },
                                )
                                .await;
                                let pid = match &resp {
                                    Response::BackgroundReady { pid } => Some(*pid),
                                    _ => None,
                                };
                                if pid.is_none() {
                                    return super::TestOutcome::new(
                                        agent.name(),
                                        false,
                                        format!("server_start failed: {resp:?}"),
                                    );
                                }
                                let data = format!("unix_{name}");
                                let resp = send_to(
                                    run,
                                    &handles,
                                    agent,
                                    MatrixOp::UnixConnect {
                                        path: sock.clone(),
                                        data: data.clone(),
                                    },
                                )
                                .await;
                                let pass = matches!(
                                    &resp,
                                    Response::Connected { echo } if *echo == data
                                );
                                if let Some(pid) = pid {
                                    let _ =
                                        send_to(run, &handles, agent, MatrixOp::Kill { pid }).await;
                                }
                                let _ = send_to(
                                    run,
                                    &handles,
                                    agent,
                                    MatrixOp::UnixUnlisten { path: sock },
                                )
                                .await;
                                super::TestOutcome::new(agent.name(), pass, format!("{resp:?}"))
                            })
                        },
                    );
                }
            }
            UnixPattern::CrossAgent => {
                let connector = tc.peer.unwrap();
                let sock_listen = sock.clone();
                matrix_test(
                    reg,
                    format!("U.{name}.listen"),
                    vec![agent],
                    move |run, handles| {
                        Box::pin(async move {
                            let resp = send_to(
                                run,
                                &handles,
                                agent,
                                MatrixOp::UnixListen {
                                    path: sock_listen.clone(),
                                },
                            )
                            .await;
                            let pass =
                                super::expect_unix_listening_path(&resp, &sock_listen).is_ok();
                            let _ = send_to(
                                run,
                                &handles,
                                agent,
                                MatrixOp::UnixUnlisten { path: sock_listen },
                            )
                            .await;
                            super::TestOutcome::new(agent.name(), pass, format!("{resp:?}"))
                        })
                    },
                );
                matrix_test(
                    reg,
                    format!("U.{name}.connect"),
                    vec![agent, connector],
                    move |run, handles| {
                        Box::pin(async move {
                            let data = format!("unix_{name}");
                            let resp = send_to(
                                run,
                                &handles,
                                agent,
                                MatrixOp::UnixListen { path: sock.clone() },
                            )
                            .await;
                            if let Err(e) = super::expect_unix_listening_path(&resp, &sock) {
                                return super::TestOutcome::new(
                                    connector.name(),
                                    false,
                                    format!("listen failed: {e}; resp={resp:?}"),
                                );
                            }
                            let resp = send_to(
                                run,
                                &handles,
                                connector,
                                MatrixOp::UnixConnect {
                                    path: sock.clone(),
                                    data: data.clone(),
                                },
                            )
                            .await;
                            let pass =
                                matches!(&resp, Response::Connected { echo } if *echo == data);
                            let _ = send_to(
                                run,
                                &handles,
                                agent,
                                MatrixOp::UnixUnlisten { path: sock },
                            )
                            .await;
                            super::TestOutcome::new(connector.name(), pass, format!("{resp:?}"))
                        })
                    },
                );
            }
        }
    }
    matrix_test(
        reg,
        "U.repro.listen",
        vec![AgentName::Dpg1Dpg1Dpg1],
        move |run, handles| {
            Box::pin(async move {
                let sock = "/tmp/um_repro_xworker.sock".to_string();
                let resp = send_to(
                    run,
                    &handles,
                    AgentName::Dpg1Dpg1Dpg1,
                    MatrixOp::UnixListen { path: sock.clone() },
                )
                .await;
                let pass = super::expect_unix_listening_path(&resp, &sock).is_ok();
                let _ = send_to(
                    run,
                    &handles,
                    AgentName::Dpg1Dpg1Dpg1,
                    MatrixOp::UnixUnlisten { path: sock },
                )
                .await;
                super::TestOutcome::new(AgentName::Dpg1Dpg1Dpg1.name(), pass, format!("{resp:?}"))
            })
        },
    );
    matrix_test(
        reg,
        "U.repro.same_agent",
        vec![AgentName::Dpg1Dpg1Dpg1],
        move |run, handles| {
            Box::pin(async move {
                let sock = "/tmp/um_repro_xworker.sock".to_string();
                let resp = send_to(
                    run,
                    &handles,
                    AgentName::Dpg1Dpg1Dpg1,
                    MatrixOp::UnixListen { path: sock.clone() },
                )
                .await;
                if let Err(e) = super::expect_unix_listening_path(&resp, &sock) {
                    return super::TestOutcome::new(
                        AgentName::Dpg1Dpg1Dpg1.name(),
                        false,
                        format!("listen failed: {e}; resp={resp:?}"),
                    );
                }
                let resp = send_to(
                    run,
                    &handles,
                    AgentName::Dpg1Dpg1Dpg1,
                    MatrixOp::UnixConnect {
                        path: sock.clone(),
                        data: "SAME_AGENT".to_string(),
                    },
                )
                .await;
                let pass =
                    matches!(&resp, Response::Connected { echo } if echo.contains("SAME_AGENT"));
                let _ = send_to(
                    run,
                    &handles,
                    AgentName::Dpg1Dpg1Dpg1,
                    MatrixOp::UnixUnlisten { path: sock },
                )
                .await;
                super::TestOutcome::new(AgentName::Dpg1Dpg1Dpg1.name(), pass, format!("{resp:?}"))
            })
        },
    );
    matrix_test(
        reg,
        "U.repro.cross_worker",
        vec![AgentName::Dpg1Dpg1Dpg1, AgentName::Dpg1Dng],
        move |run, handles| {
            Box::pin(async move {
                let sock = "/tmp/um_repro_xworker.sock".to_string();
                let resp = send_to(
                    run,
                    &handles,
                    AgentName::Dpg1Dpg1Dpg1,
                    MatrixOp::UnixListen { path: sock.clone() },
                )
                .await;
                if let Err(e) = super::expect_unix_listening_path(&resp, &sock) {
                    return super::TestOutcome::new(
                        AgentName::Dpg1Dng.name(),
                        false,
                        format!("listen failed: {e}; resp={resp:?}"),
                    );
                }
                let resp = send_to(
                    run,
                    &handles,
                    AgentName::Dpg1Dng,
                    MatrixOp::UnixConnect {
                        path: sock.clone(),
                        data: "CROSS_WORKER".to_string(),
                    },
                )
                .await;
                let pass =
                    matches!(&resp, Response::Connected { echo } if echo.contains("CROSS_WORKER"));
                let _ = send_to(
                    run,
                    &handles,
                    AgentName::Dpg1Dpg1Dpg1,
                    MatrixOp::UnixUnlisten { path: sock },
                )
                .await;
                super::TestOutcome::new(AgentName::Dpg1Dng.name(), pass, format!("{resp:?}"))
            })
        },
    );
}

pub(super) fn register_matrix(reg: &mut Registry<'_>) {
    register_matrix_handlers();
    register_fs_crud(reg);
    register_fs_cross_unlink(reg);
    register_tmp_isolation(reg);
    register_host_file(reg);
    register_net_tests(reg);
    register_net_addr_tests(reg);
    register_unix_addr_tests(reg);
    register_exec_tests(reg);
    register_env_tests(reg);
    register_symlink_basic(reg);
    register_symlink_variants(reg);
    register_unix_tests(reg);
}
