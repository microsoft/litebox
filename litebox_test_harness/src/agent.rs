// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Agent command executor. Reads commands from stdin, executes them,
//! writes responses to stdout. Intermediate nodes forward commands to
//! their children.

use crate::protocol::{Command, Response};
use std::collections::HashMap;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::time::Duration;

struct ChildHandle {
    stdin: tokio::process::ChildStdin,
    stdout: BufReader<tokio::process::ChildStdout>,
    #[allow(dead_code)]
    process: tokio::process::Child,
}

/// Run the agent. Reads commands from stdin, executes, responds on stdout.
pub fn run(self_exe: &str) {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(agent_loop(self_exe));
}

async fn agent_loop(self_exe: &str) {
    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin);
    let mut children: HashMap<String, ChildHandle> = HashMap::new();
    let mut listeners: HashMap<u16, tokio::task::JoinHandle<()>> = HashMap::new();

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
                    match spawn_child(self_exe, name).await {
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

            Command::FsRead { path } => match tokio::fs::read_to_string(&path).await {
                Ok(data) => respond(&Response::Ok { data: Some(data) }).await,
                Err(_) => respond(&Response::NotFound).await,
            },

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

            Command::NetListen { port } => {
                match TcpListener::bind(format!("0.0.0.0:{port}")).await {
                    Ok(listener) => {
                        // Spawn echo server task.
                        let task = tokio::spawn(async move {
                            loop {
                                match listener.accept().await {
                                    Ok((mut stream, _)) => {
                                        tokio::spawn(async move {
                                            let mut buf = [0u8; 4096];
                                            loop {
                                                match stream.read(&mut buf).await {
                                                    Ok(0) | Err(_) => break,
                                                    Ok(n) => {
                                                        if stream.write_all(&buf[..n]).await.is_err()
                                                        {
                                                            break;
                                                        }
                                                    }
                                                }
                                            }
                                        });
                                    }
                                    Err(_) => break,
                                }
                            }
                        });
                        listeners.insert(port, task);
                        respond(&Response::Listening { port }).await;
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

            Command::Exec { args, timeout_secs } => {
                if args.is_empty() {
                    respond(&Response::Error {
                        error: "exec requires args".to_string(),
                    })
                    .await;
                    continue;
                }
                let timeout = Duration::from_secs(timeout_secs.unwrap_or(10));
                let mut child = match tokio::process::Command::new(&args[0])
                    .args(&args[1..])
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .spawn()
                {
                    Ok(c) => c,
                    Err(e) => {
                        respond(&Response::Error {
                            error: format!("exec spawn: {e}"),
                        })
                        .await;
                        continue;
                    }
                };
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
                            stdout: String::from_utf8_lossy(&out).trim().to_string(),
                            stderr: String::from_utf8_lossy(&err).trim().to_string(),
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
                        // Timed out — kill the child and report timeout.
                        let _ = child.kill().await;
                        respond(&Response::ExecTimeout {
                            stderr: "process timed out after 10s (likely deadlocked)".to_string(),
                        })
                        .await;
                    }
                }
            }

            Command::EnvGet { var } => {
                let val = std::env::var(&var).unwrap_or_else(|_| "NOT_SET".to_string());
                respond(&Response::Ok {
                    data: Some(val),
                })
                .await;
            }

            Command::CwdGet => {
                let cwd = std::env::current_dir()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|e| format!("ERROR: {e}"));
                respond(&Response::Ok {
                    data: Some(cwd),
                })
                .await;
            }

            Command::Go => {
                respond(&Response::Ok { data: None }).await;
            }

            Command::UnixSocketTest { path } => {
                let result = unix_socket_test(&path).await;
                respond(&result).await;
            }

            Command::UnixSocketRelay { path, self_exe } => {
                let result = unix_socket_relay_test(&path, &self_exe).await;
                respond(&result).await;
            }

            Command::UnixSocketReverseRelay { path, self_exe } => {
                let result = unix_socket_reverse_relay_test(&path, &self_exe).await;
                respond(&result).await;
            }

            Command::Exit => {
                // Abort all echo servers.
                for (_, task) in listeners.drain() {
                    task.abort();
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

async fn spawn_child(self_exe: &str, id: &str) -> Result<ChildHandle, String> {
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
    match tokio::time::timeout(Duration::from_secs(15), child.stdout.read_line(&mut line)).await {
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

/// Test Unix domain socket lifecycle: create, bind, listen, accept+connect, send/recv.
async fn unix_socket_test(path: &str) -> Response {
    use tokio::net::{UnixListener, UnixStream};

    // Clean up any leftover socket file.
    let _ = tokio::fs::remove_file(path).await;

    // Step 1: Bind and listen.
    let listener = match UnixListener::bind(path) {
        Ok(l) => l,
        Err(e) => {
            return Response::Error {
                error: format!("unix bind({path}): {e}"),
            };
        }
    };

    // Step 2: Connect from a client task.
    let path_owned = path.to_string();
    let client = tokio::spawn(async move {
        let mut stream = UnixStream::connect(&path_owned).await?;
        tokio::io::AsyncWriteExt::write_all(&mut stream, b"UNIX_HELLO").await?;
        tokio::io::AsyncWriteExt::flush(&mut stream).await?;
        let mut buf = [0u8; 64];
        let n = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await?;
        Ok::<String, std::io::Error>(String::from_utf8_lossy(&buf[..n]).to_string())
    });

    // Step 3: Accept and echo.
    let accept_result = tokio::time::timeout(Duration::from_secs(5), async {
        let (mut stream, _) = listener.accept().await?;
        let mut buf = [0u8; 64];
        let n = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await?;
        tokio::io::AsyncWriteExt::write_all(&mut stream, &buf[..n]).await?;
        Ok::<usize, std::io::Error>(n)
    })
    .await;

    // Clean up.
    drop(listener);
    let _ = tokio::fs::remove_file(path).await;

    // Check results.
    match accept_result {
        Err(_) => Response::Error {
            error: "unix accept timeout".to_string(),
        },
        Ok(Err(e)) => Response::Error {
            error: format!("unix accept/echo: {e}"),
        },
        Ok(Ok(_)) => match client.await {
            Ok(Ok(echo)) if echo == "UNIX_HELLO" => Response::Ok {
                data: Some("unix_socket_ok".to_string()),
            },
            Ok(Ok(echo)) => Response::Error {
                error: format!("unix echo mismatch: got {echo:?}"),
            },
            Ok(Err(e)) => Response::Error {
                error: format!("unix client: {e}"),
            },
            Err(e) => Response::Error {
                error: format!("unix client task: {e}"),
            },
        },
    }
}

/// Test cross-process Unix socket relay: start a server in this process,
/// fork a child (via self_exe unix-echo-client) that connects and sends data,
/// verify the echo round-trip. This mimics the CLI↔code-server path where
/// the CLI creates a Unix socket and code-server (a forked child) connects to it.
async fn unix_socket_relay_test(path: &str, self_exe: &str) -> Response {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let _ = tokio::fs::remove_file(path).await;

    // Step 1: Bind and listen.
    let listener = match tokio::net::UnixListener::bind(path) {
        Ok(l) => l,
        Err(e) => {
            return Response::Error {
                error: format!("relay bind({path}): {e}"),
            };
        }
    };

    // Step 2: Fork a child process that connects and sends data.
    let mut child = match tokio::process::Command::new(self_exe)
        .args(["unix-echo-client", path, "RELAY_TEST_DATA"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            let _ = tokio::fs::remove_file(path).await;
            return Response::Error {
                error: format!("relay spawn client: {e}"),
            };
        }
    };

    // Step 3: Accept the connection and echo data back.
    let accept_result = tokio::time::timeout(Duration::from_secs(5), async {
        let (mut stream, _) = listener.accept().await?;
        let mut buf = [0u8; 4096];
        let n = stream.read(&mut buf).await?;
        stream.write_all(&buf[..n]).await?;
        stream.flush().await?;
        Ok::<usize, std::io::Error>(n)
    })
    .await;

    // Step 4: Wait for the child and read its output.
    let child_result =
        tokio::time::timeout(Duration::from_secs(5), child.wait_with_output()).await;

    drop(listener);
    let _ = tokio::fs::remove_file(path).await;

    match accept_result {
        Err(_) => Response::Error {
            error: "relay accept timeout (client never connected)".to_string(),
        },
        Ok(Err(e)) => Response::Error {
            error: format!("relay accept/echo: {e}"),
        },
        Ok(Ok(_)) => match child_result {
            Ok(Ok(output)) => {
                let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
                let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
                if stdout == "RELAY_TEST_DATA" {
                    Response::Ok {
                        data: Some("unix_relay_ok".to_string()),
                    }
                } else {
                    Response::Error {
                        error: format!("relay got: {stdout:?} stderr: {stderr:?}"),
                    }
                }
            }
            Ok(Err(e)) => Response::Error {
                error: format!("relay client wait: {e}"),
            },
            Err(_) => Response::Error {
                error: "relay client timeout".to_string(),
            },
        },
    }
}

/// Reverse relay: fork a child that creates a Unix socket server, then the
/// parent connects as client. Mimics VS Code's pattern where code-server
/// (child) creates the socket and CLI (parent) connects to it.
async fn unix_socket_reverse_relay_test(path: &str, self_exe: &str) -> Response {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let _ = tokio::fs::remove_file(path).await;

    // Step 1: Fork a child that runs unix-echo-server (binds, listens, accepts, echoes).
    let mut child = match tokio::process::Command::new(self_exe)
        .args(["unix-echo-server", path])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            return Response::Error {
                error: format!("reverse relay spawn server: {e}"),
            };
        }
    };

    // Step 2: Wait for the child to print "LISTENING" (socket is ready).
    let mut child_stdout = child.stdout.take().unwrap();
    let ready = tokio::time::timeout(Duration::from_secs(5), async {
        let mut buf = [0u8; 256];
        let n = child_stdout.read(&mut buf).await?;
        let output = String::from_utf8_lossy(&buf[..n]);
        Ok::<bool, std::io::Error>(output.contains("LISTENING"))
    })
    .await;

    let is_ready = matches!(ready, Ok(Ok(true)));
    if !is_ready {
        let _ = child.kill().await;
        let _ = tokio::fs::remove_file(path).await;
        return Response::Error {
            error: format!("reverse relay server not ready: {ready:?}"),
        };
    }

    // Step 3: Parent connects to the child's socket and sends data.
    let connect_result = tokio::time::timeout(Duration::from_secs(5), async {
        let mut stream = tokio::net::UnixStream::connect(path).await?;
        stream.write_all(b"REVERSE_RELAY_DATA").await?;
        stream.flush().await?;
        let mut buf = [0u8; 4096];
        let n = stream.read(&mut buf).await?;
        Ok::<String, std::io::Error>(String::from_utf8_lossy(&buf[..n]).to_string())
    })
    .await;

    // Step 4: Wait for child to exit.
    let _ = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
    let _ = child.kill().await;
    let _ = tokio::fs::remove_file(path).await;

    match connect_result {
        Err(_) => Response::Error {
            error: "reverse relay connect timeout".to_string(),
        },
        Ok(Err(e)) => Response::Error {
            error: format!("reverse relay connect: {e}"),
        },
        Ok(Ok(echo)) => {
            if echo == "REVERSE_RELAY_DATA" {
                Response::Ok {
                    data: Some("unix_reverse_relay_ok".to_string()),
                }
            } else {
                Response::Error {
                    error: format!("reverse relay echo mismatch: got {echo:?}"),
                }
            }
        }
    }
}
