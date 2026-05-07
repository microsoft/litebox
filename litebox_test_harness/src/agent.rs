// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Agent command executor. Reads commands from stdin, executes them,
//! writes responses to stdout. Intermediate nodes forward commands to
//! their children.

use crate::protocol::{Command, Response};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::Duration;

struct ChildHandle {
    stdin: tokio::process::ChildStdin,
    stdout: BufReader<tokio::process::ChildStdout>,
    #[allow(dead_code)]
    process: tokio::process::Child,
}

type TcpConn = Arc<tokio::sync::Mutex<TcpStream>>;

/// Run the agent. Reads commands from stdin, executes, responds on stdout.
pub fn run(self_exe: &str) {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(agent_loop(self_exe));
}

#[allow(clippy::too_many_lines)] // exhaustive runner / dispatch table
async fn agent_loop(self_exe: &str) {
    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin);
    let mut children: HashMap<String, ChildHandle> = HashMap::new();
    let mut listeners: HashMap<u16, tokio::task::JoinHandle<()>> = HashMap::new();
    let mut unix_listeners: HashMap<String, tokio::task::JoinHandle<()>> = HashMap::new();
    let mut connections: HashMap<u64, TcpConn> = HashMap::new();
    let mut next_conn_id = 1u64;
    let mut background_pids: Vec<tokio::process::Child> = Vec::new();

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
                    _ => self_exe.to_string(), // "self" or default
                };

                // inherit_listen_ports is tracked for future use.
                let _ = &inherit_listen_ports;

                match spawn_child(&exe, &name) {
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

            Command::NetListen { port } => {
                match TcpListener::bind(format!("0.0.0.0:{port}")).await {
                    Ok(listener) => {
                        let actual_port = listener.local_addr().map(|a| a.port()).unwrap_or(port);
                        // Spawn echo server task.
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
                        listeners.insert(actual_port, task);
                        respond(&Response::Listening { port: actual_port }).await;
                    }
                    Err(e) => {
                        respond(&Response::Error {
                            error: format!("bind {port}: {e}"),
                        })
                        .await;
                    }
                }
            }

            Command::NetUnlisten { port } => {
                if let Some(task) = listeners.remove(&port) {
                    task.abort();
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
                if next_conn_id == u64::MAX {
                    respond(&Response::Error {
                        error: "connection id space exhausted".to_string(),
                    })
                    .await;
                    continue;
                }
                match tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(&addr)).await
                {
                    Ok(Ok(stream)) => {
                        let conn = next_conn_id;
                        next_conn_id += 1;
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

            Command::Exec {
                args,
                timeout_secs,
                stdin: stdin_content,
                background,
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
                            background_pids.push(child);
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

            Command::PollReady { timeout_ms } => {
                // Create a pipe, write data, poll read-end for POLLIN.
                let result = (|| -> Result<&str, String> {
                    let mut pipe_fds = [0i32; 2];
                    if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } != 0 {
                        return Err("pipe() failed".into());
                    }
                    let (read_fd, write_fd) = (pipe_fds[0], pipe_fds[1]);
                    let data = b"poll_test_data";
                    unsafe {
                        libc::write(write_fd, data.as_ptr().cast(), data.len());
                    }
                    let mut fds = [libc::pollfd {
                        fd: read_fd,
                        events: libc::POLLIN,
                        revents: 0,
                    }];
                    let n = unsafe { libc::poll(fds.as_mut_ptr(), 1, timeout_ms as i32) };
                    unsafe {
                        libc::close(write_fd);
                        libc::close(read_fd);
                    }
                    if n > 0 && (fds[0].revents & libc::POLLIN) != 0 {
                        Ok("POLLIN")
                    } else {
                        Ok("TIMEOUT")
                    }
                })();
                match result {
                    Ok(status) => {
                        respond(&Response::Ok {
                            data: Some(status.to_string()),
                        })
                        .await;
                    }
                    Err(e) => respond(&Response::Error { error: e }).await,
                }
            }

            Command::BindGetsockname { family } => {
                let result = match family.as_str() {
                    "ipv4" => {
                        let sock = std::net::TcpListener::bind("0.0.0.0:0");
                        sock.map(|s| s.local_addr().map(|a| a.port()).unwrap_or(0))
                            .map_err(|e| format!("{e}"))
                    }
                    "ipv6" => {
                        let sock = std::net::TcpListener::bind("[::]:0");
                        sock.map(|s| s.local_addr().map(|a| a.port()).unwrap_or(0))
                            .map_err(|e| format!("{e}"))
                    }
                    other => Err(format!("unknown family: {other}")),
                };
                match result {
                    Ok(port) => {
                        respond(&Response::Ok {
                            data: Some(format!("port={port}")),
                        })
                        .await;
                    }
                    Err(e) => respond(&Response::Error { error: e }).await,
                }
            }

            Command::PipePairIdUnique { count } => {
                // Create+drop pipes, then create more and check for inode reuse.
                // On native Linux inodes are unique so this always passes.
                // On litebox, Arc::as_ptr() pair_ids could collide after free.
                use std::collections::HashSet;
                let result = (|| -> Result<String, String> {
                    let mut first_batch = HashSet::new();
                    let mut fds = Vec::new();
                    for _ in 0..count {
                        let mut pipe_fds = [0i32; 2];
                        if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } != 0 {
                            return Err("pipe() failed".into());
                        }
                        // Use inode as proxy for pair_id.
                        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
                        if unsafe { libc::fstat(pipe_fds[0], &raw mut stat) } == 0 {
                            first_batch.insert(stat.st_ino);
                        }
                        fds.push(pipe_fds);
                    }
                    for pipe_fds in fds.drain(..) {
                        unsafe {
                            libc::close(pipe_fds[0]);
                            libc::close(pipe_fds[1]);
                        }
                    }
                    let mut collisions = 0u32;
                    for _ in 0..count {
                        let mut pipe_fds = [0i32; 2];
                        if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } != 0 {
                            return Err("pipe() failed".into());
                        }
                        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
                        if unsafe { libc::fstat(pipe_fds[0], &raw mut stat) } == 0
                            && first_batch.contains(&stat.st_ino)
                        {
                            collisions += 1;
                        }
                        unsafe {
                            libc::close(pipe_fds[0]);
                            libc::close(pipe_fds[1]);
                        }
                    }
                    if collisions > 0 {
                        Err(format!("collision: {collisions}/{count} ids reused"))
                    } else {
                        Ok("unique".to_string())
                    }
                })();
                match result {
                    Ok(msg) => respond(&Response::Ok { data: Some(msg) }).await,
                    Err(e) => respond(&Response::Error { error: e }).await,
                }
            }

            Command::Kill { pid } => {
                // Try to kill by pid. Also clean up our background_pids list.
                let mut killed = false;
                background_pids.retain_mut(|child| {
                    if child.id() == Some(pid) {
                        let _ = child.start_kill();
                        killed = true;
                        false // remove from list
                    } else {
                        true
                    }
                });
                if !killed {
                    // Try OS-level kill as fallback.
                    unsafe {
                        libc::kill(pid as i32, libc::SIGKILL);
                    }
                }
                respond(&Response::Ok { data: None }).await;
            }

            Command::NetConnectMany {
                addr,
                data,
                count,
                delay_ms,
            } => {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut handles = Vec::new();
                for _i in 0..count {
                    let addr = addr.clone();
                    let data = data.clone();
                    handles.push(tokio::spawn(async move {
                        let Ok(Ok(mut stream)) = tokio::time::timeout(
                            Duration::from_secs(5),
                            tokio::net::TcpStream::connect(&addr),
                        )
                        .await
                        else {
                            return false;
                        };
                        if stream.write_all(data.as_bytes()).await.is_err() {
                            return false;
                        }
                        let _ = stream.flush().await;
                        let _ = stream.shutdown().await;
                        let mut buf = vec![0u8; data.len() + 64];
                        match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
                            .await
                        {
                            Ok(Ok(n)) if n > 0 => String::from_utf8_lossy(&buf[..n]) == data,
                            _ => false,
                        }
                    }));
                    if delay_ms > 0 {
                        tokio::time::sleep(Duration::from_millis(u64::from(delay_ms))).await;
                    }
                }
                let mut success = 0u32;
                for h in handles {
                    if let Ok(true) = h.await {
                        success += 1;
                    }
                }
                respond(&Response::Ok {
                    data: Some(format!("success={success}/{count}")),
                })
                .await;
            }

            Command::NetSendRecv { addr, size } => {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let result = async {
                    let mut stream = tokio::time::timeout(
                        Duration::from_secs(10),
                        tokio::net::TcpStream::connect(&addr),
                    )
                    .await
                    .map_err(|_| "connect timeout".to_string())?
                    .map_err(|e| format!("connect: {e}"))?;

                    // Generate known pattern.
                    let pattern: Vec<u8> = (0..size as usize)
                        .map(|i| b"ABCDEFGHIJKLMNOP"[i % 16])
                        .collect();
                    stream
                        .write_all(&pattern)
                        .await
                        .map_err(|e| format!("write: {e}"))?;
                    let _ = stream.shutdown().await;

                    // Read echoed data.
                    let mut received = Vec::new();
                    let mut buf = [0u8; 8192];
                    loop {
                        match tokio::time::timeout(Duration::from_secs(10), stream.read(&mut buf))
                            .await
                        {
                            Ok(Ok(0)) => break,
                            Ok(Ok(n)) => {
                                received.extend_from_slice(&buf[..n]);
                            }
                            Ok(Err(e)) => return Err(format!("read: {e}")),
                            Err(_) => return Err("read timeout".to_string()),
                        }
                    }

                    // Verify integrity.
                    if received.len() != pattern.len() {
                        return Err(format!(
                            "size mismatch: sent={} recv={}",
                            pattern.len(),
                            received.len()
                        ));
                    }
                    if received != pattern {
                        let first_diff = received
                            .iter()
                            .zip(pattern.iter())
                            .position(|(a, b)| a != b)
                            .unwrap_or(0);
                        return Err(format!(
                            "data mismatch at byte {first_diff}: got {:02x} expected {:02x}",
                            received[first_diff], pattern[first_diff]
                        ));
                    }
                    Ok(format!("verified={size}"))
                }
                .await;
                match result {
                    Ok(msg) => respond(&Response::Ok { data: Some(msg) }).await,
                    Err(e) => respond(&Response::Error { error: e }).await,
                }
            }

            Command::NetReconnectStress { addr, count, data } => {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut success = 0u32;
                for _ in 0..count {
                    let ok = async {
                        let mut stream = tokio::time::timeout(
                            Duration::from_secs(5),
                            tokio::net::TcpStream::connect(&addr),
                        )
                        .await
                        .ok()?
                        .ok()?;
                        stream.write_all(data.as_bytes()).await.ok()?;
                        let _ = stream.flush().await;
                        let _ = stream.shutdown().await;
                        let mut buf = vec![0u8; data.len() + 64];
                        let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
                            .await
                            .ok()?
                            .ok()?;
                        if n == data.len() && String::from_utf8_lossy(&buf[..n]) == data {
                            Some(())
                        } else {
                            None
                        }
                    }
                    .await;
                    if ok.is_some() {
                        success += 1;
                    }
                }
                respond(&Response::Ok {
                    data: Some(format!("success={success}/{count}")),
                })
                .await;
            }

            Command::NetSendFileRecv { addr, size, path } => {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let result = async {
                    // 1. Connect and send data.
                    let mut stream = tokio::time::timeout(
                        Duration::from_secs(10),
                        tokio::net::TcpStream::connect(&addr),
                    )
                    .await
                    .map_err(|_| "connect timeout".to_string())?
                    .map_err(|e| format!("connect: {e}"))?;

                    let pattern: Vec<u8> = (0..size as usize)
                        .map(|i| b"ABCDEFGHIJKLMNOP"[i % 16])
                        .collect();
                    stream
                        .write_all(&pattern)
                        .await
                        .map_err(|e| format!("write: {e}"))?;
                    let _ = stream.flush().await;

                    // 2. Read a file while the TCP socket is still open.
                    //    This is the operation that triggers 9P deadlock in litebox:
                    //    sys_openat → 9P client → wait_for_completion (hangs).
                    let file_content = tokio::fs::read_to_string(&path)
                        .await
                        .map_err(|e| format!("file read({path}): {e}"))?;

                    // 3. Shutdown write side and read echoed data.
                    let _ = stream.shutdown().await;
                    let mut received = Vec::new();
                    let mut buf = [0u8; 8192];
                    loop {
                        match tokio::time::timeout(Duration::from_secs(10), stream.read(&mut buf))
                            .await
                        {
                            Ok(Ok(0)) => break,
                            Ok(Ok(n)) => received.extend_from_slice(&buf[..n]),
                            Ok(Err(e)) => return Err(format!("read: {e}")),
                            Err(_) => return Err("read timeout".to_string()),
                        }
                    }

                    // 4. Verify TCP data integrity.
                    if received.len() != pattern.len() {
                        return Err(format!(
                            "size mismatch: sent={} recv={}",
                            pattern.len(),
                            received.len()
                        ));
                    }
                    if received != pattern {
                        let first_diff = received
                            .iter()
                            .zip(pattern.iter())
                            .position(|(a, b)| a != b)
                            .unwrap_or(0);
                        return Err(format!(
                            "data mismatch at byte {first_diff}: got {:02x} expected {:02x}",
                            received[first_diff], pattern[first_diff]
                        ));
                    }
                    Ok(format!("tcp_ok={size},file_len={}", file_content.len()))
                }
                .await;
                match result {
                    Ok(msg) => respond(&Response::Ok { data: Some(msg) }).await,
                    Err(e) => respond(&Response::Error { error: e }).await,
                }
            }

            Command::Exit => {
                // Abort all TCP echo servers.
                for (_, task) in listeners.drain() {
                    task.abort();
                }
                // Abort all Unix echo servers.
                for (_, task) in unix_listeners.drain() {
                    task.abort();
                }
                // Kill background processes.
                for mut child in background_pids.drain(..) {
                    let _ = child.kill().await;
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

fn spawn_child(self_exe: &str, _id: &str) -> Result<ChildHandle, String> {
    let mut child = tokio::process::Command::new(self_exe)
        .arg("agent")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .map_err(|e| format!("{e}"))?;

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
