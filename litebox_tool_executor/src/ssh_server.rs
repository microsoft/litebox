// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Embedded SSH server for VS Code Remote connections.
//!
//! Listens on `localhost:<port>`, accepts SSH connections, and bridges each
//! session's channel I/O to a litebox runner subprocess running VS Code Server.
//! This lets VS Code's standard Remote-SSH extension connect without any shims,
//! global setting overrides, or custom profiles.
//!
//! Usage from the tool executor:
//! ```text
//! litebox-tool-executor --rootfs /path/to/vscode-rootfs --vscode-server
//! ```
//! Prints `SSH listening on 127.0.0.1:<port>` to stderr. Connect with:
//! ```text
//! Remote-SSH: Connect to Host → localhost:<port>
//! ```

use std::sync::Arc;

use russh::server::{Msg, Server as _, Session};
use russh::{Channel, ChannelId};
#[cfg(unix)]
use std::os::unix::process::CommandExt as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command as TokioCommand;
use tokio::sync::Mutex;

/// Configuration for launching the litebox runner.
#[derive(Clone)]
pub struct LiteboxConfig {
    pub runner_path: String,
    pub broker_socket: String,
    pub rootfs: String,
    pub audit_log: Option<String>,
    pub extra_env: Vec<String>,
    pub extra_args: Vec<String>,
}

/// SSH server state.
#[derive(Clone)]
struct SshServer {
    litebox_config: Arc<LiteboxConfig>,
}

impl russh::server::Server for SshServer {
    type Handler = SshSession;

    fn new_client(&mut self, peer: Option<std::net::SocketAddr>) -> Self::Handler {
        eprintln!(
            "[ssh] new connection from {}",
            peer.map(|a| a.to_string())
                .unwrap_or_else(|| "unknown".into())
        );
        SshSession {
            litebox_config: self.litebox_config.clone(),
            child: Arc::new(Mutex::new(None)),
        }
    }
}

/// Per-connection SSH session handler.
struct SshSession {
    litebox_config: Arc<LiteboxConfig>,
    child: Arc<Mutex<Option<ChildBridge>>>,
}

/// Holds the spawned litebox child process and its stdin handle.
struct ChildBridge {
    stdin: tokio::process::ChildStdin,
    _stdout_task: tokio::task::JoinHandle<()>,
    _stderr_task: tokio::task::JoinHandle<()>,
}

impl Clone for SshSession {
    fn clone(&self) -> Self {
        Self {
            litebox_config: self.litebox_config.clone(),
            child: self.child.clone(),
        }
    }
}

impl SshSession {
    /// Spawn the litebox runner as a child process and bridge its I/O to the
    /// SSH channel.
    async fn spawn_litebox(
        &self,
        channel_id: ChannelId,
        session_handle: russh::server::Handle,
    ) -> Result<(), anyhow::Error> {
        let cfg = &self.litebox_config;

        let mut cmd = TokioCommand::new(&cfg.runner_path);
        cmd.arg("--unstable");
        cmd.arg("--network-broker").arg(&cfg.broker_socket);
        cmd.arg("--nine-p-broker").arg(&cfg.broker_socket);

        if let Some(ref audit) = cfg.audit_log {
            cmd.arg("--audit-log").arg(audit);
        }

        // Environment
        for kv in &cfg.extra_env {
            cmd.arg("--env").arg(kv);
        }

        cmd.arg("--");
        cmd.arg("/usr/local/bin/node");
        cmd.arg("/opt/vscode-server/out/server-main.js");
        cmd.args([
            "--accept-server-license-terms",
            "--without-connection-token",
            "--disable-telemetry",
            "--host",
            "127.0.0.1",
            "--port",
            "0",
        ]);

        for arg in &cfg.extra_args {
            cmd.arg(arg);
        }

        cmd.stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());

        // Reset signal handlers to SIG_DFL in the child process before exec.
        // Tokio installs a SIGINT handler; the litebox runner asserts that
        // signal handlers are at their defaults on startup.
        #[cfg(unix)]
        unsafe {
            cmd.pre_exec(|| {
                for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGQUIT, libc::SIGHUP] {
                    libc::signal(sig, libc::SIG_DFL);
                }
                Ok(())
            });
        }

        let mut child = cmd
            .spawn()
            .map_err(|e| anyhow::anyhow!("Failed to spawn litebox runner: {e}"))?;

        let stdin = child.stdin.take().unwrap();
        let mut stdout = child.stdout.take().unwrap();
        let mut stderr = child.stderr.take().unwrap();

        // Forward subprocess stdout → SSH channel data
        let handle_out = session_handle.clone();
        let stdout_task = tokio::spawn(async move {
            let mut buf = [0u8; 8192];
            loop {
                match stdout.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if handle_out
                            .data(channel_id, bytes::Bytes::copy_from_slice(&buf[..n]))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            let _ = handle_out.eof(channel_id).await;
            let _ = handle_out.close(channel_id).await;
        });

        // Forward subprocess stderr → SSH channel extended data (stderr)
        let handle_err = session_handle;
        let stderr_task = tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                match stderr.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if handle_err
                            .extended_data(channel_id, 1, bytes::Bytes::copy_from_slice(&buf[..n]))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        // Wait for child in the background
        tokio::spawn(async move {
            let _ = child.wait().await;
        });

        *self.child.lock().await = Some(ChildBridge {
            stdin,
            _stdout_task: stdout_task,
            _stderr_task: stderr_task,
        });

        Ok(())
    }
}

impl russh::server::Handler for SshSession {
    type Error = anyhow::Error;

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        eprintln!("[ssh] session channel opened (id={})", channel.id());
        // Don't spawn yet — wait for exec_request or shell_request from the
        // client. VS Code Remote-SSH opens the channel first, sends env vars,
        // then sends an exec request with the server startup command.
        Ok(true)
    }

    async fn exec_request(
        &mut self,
        channel_id: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let cmd = String::from_utf8_lossy(data);
        eprintln!("[ssh] exec request: {cmd}");
        // VS Code sends a command to start the server. We ignore the command
        // and always launch our litebox VS Code Server instead.
        self.spawn_litebox(channel_id, session.handle()).await?;
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel_id: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        eprintln!("[ssh] shell request");
        self.spawn_litebox(channel_id, session.handle()).await?;
        Ok(())
    }

    async fn auth_publickey(
        &mut self,
        _user: &str,
        _key: &russh::keys::PublicKey,
    ) -> Result<russh::server::Auth, Self::Error> {
        // Accept any key — we're localhost-only.
        Ok(russh::server::Auth::Accept)
    }

    async fn auth_password(
        &mut self,
        _user: &str,
        _password: &str,
    ) -> Result<russh::server::Auth, Self::Error> {
        // Accept any password — we're localhost-only.
        Ok(russh::server::Auth::Accept)
    }

    async fn auth_none(&mut self, _user: &str) -> Result<russh::server::Auth, Self::Error> {
        Ok(russh::server::Auth::Accept)
    }

    async fn data(
        &mut self,
        _channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Forward SSH channel data → subprocess stdin
        if let Some(ref mut bridge) = *self.child.lock().await {
            bridge.stdin.write_all(data).await?;
            bridge.stdin.flush().await?;
        }
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        _channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Client closed their end — close subprocess stdin
        if let Some(ref mut bridge) = *self.child.lock().await {
            bridge.stdin.shutdown().await.ok();
        }
        Ok(())
    }
}

/// Start the embedded SSH server on `127.0.0.1:0` (random port) and return
/// the assigned port. The server runs until the returned handle is dropped
/// or the process exits.
pub async fn start_ssh_server(
    config: LiteboxConfig,
) -> Result<(u16, tokio::task::JoinHandle<()>), anyhow::Error> {
    let ssh_config = russh::server::Config {
        inactivity_timeout: Some(std::time::Duration::from_secs(3600)),
        auth_rejection_time: std::time::Duration::from_secs(0),
        auth_rejection_time_initial: Some(std::time::Duration::from_secs(0)),
        keys: vec![
            russh::keys::PrivateKey::random(
                &mut russh::keys::key::safe_rng(),
                russh::keys::Algorithm::Ed25519,
            )
            .unwrap(),
        ],
        ..Default::default()
    };
    let ssh_config = Arc::new(ssh_config);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();

    let mut server = SshServer {
        litebox_config: Arc::new(config),
    };

    let handle = tokio::spawn(async move {
        if let Err(e) = server.run_on_socket(ssh_config, &listener).await {
            eprintln!("[ssh] server error: {e}");
        }
    });

    Ok((port, handle))
}
