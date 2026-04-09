// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! CLI entrypoint for the LiteBox tool executor.
//!
//! Supports two modes:
//! - **Direct mode**: `litebox-tool-executor --rootfs rootfs.tar -- /usr/bin/bash -c "echo hello"`
//! - **Interactive shell**: `litebox-tool-executor --rootfs rootfs.tar --interactive`
//!   Launches a persistent bash session inside a single sandbox. Shell state
//!   (cd, env vars, etc.) persists across commands.
//!
//! Spawns `litebox_broker` and `litebox_runner_linux_userland` as subprocesses.
//! The broker enforces sandbox policy (filesystem + network), while the runner
//! provides the actual sandbox execution environment.

use clap::Parser as _;

#[derive(clap::Parser, Debug)]
#[command(name = "litebox-tool-executor")]
/// Execute Linux commands in a LiteBox sandbox.
struct Cli {
    /// Path to a .tar rootfs containing syscall-rewritten Linux binaries.
    #[arg(long, value_name = "PATH", value_hint = clap::ValueHint::FilePath)]
    rootfs: std::path::PathBuf,

    /// Path to a JSON policy file restricting guest operations.
    /// When provided, the broker enforces filesystem and network policy.
    #[arg(long, value_name = "PATH", value_hint = clap::ValueHint::FilePath)]
    policy: Option<std::path::PathBuf>,

    /// Run a persistent interactive shell inside the sandbox.
    /// Shell state (cd, environment variables) persists across commands.
    #[arg(long)]
    interactive: bool,

    /// Path to write the audit log (JSON lines).
    #[arg(long = "audit-log", value_name = "PATH", value_hint = clap::ValueHint::FilePath)]
    audit_log: Option<std::path::PathBuf>,

    /// Shell binary inside the rootfs to use for interactive mode (default: /usr/bin/bash).
    #[arg(long, default_value = "/usr/bin/bash")]
    shell: String,

    /// Environment variables passed to the program (`KEY=VALUE`; repeatable).
    #[arg(long = "env")]
    env: Vec<String>,

    /// The command and arguments to run. Omit for interactive mode.
    #[arg(trailing_var_arg = true)]
    command: Vec<String>,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    if !cli.rootfs.exists() {
        anyhow::bail!(
            "Rootfs tar not found: {}\n\
             Build it with: bash litebox_tool_executor/scripts/prepare-bash-rootfs.sh",
            cli.rootfs.display()
        );
    }

    if cli.interactive {
        interactive(&cli)
    } else {
        direct(&cli)
    }
}

/// Find the litebox_runner_linux_userland binary.
fn find_runner() -> anyhow::Result<std::path::PathBuf> {
    // 1. Check env var (set by cargo test / nextest)
    if let Ok(path) = std::env::var("LITEBOX_RUNNER") {
        let p = std::path::PathBuf::from(path);
        if p.exists() {
            return Ok(p);
        }
    }

    // 2. Look next to our own binary
    if let Ok(exe) = std::env::current_exe() {
        let sibling = exe
            .parent()
            .unwrap_or(std::path::Path::new("."))
            .join("litebox_runner_linux_userland");
        if sibling.exists() {
            return Ok(sibling);
        }
    }

    // 3. Try well-known workspace build paths
    for candidate in [
        "/mnt/c/src/litebox/target/debug/litebox_runner_linux_userland",
        "./target/debug/litebox_runner_linux_userland",
    ] {
        let p = std::path::PathBuf::from(candidate);
        if p.exists() {
            return Ok(p);
        }
    }

    anyhow::bail!(
        "Could not find litebox_runner_linux_userland. \
         Set LITEBOX_RUNNER env var or build it with: \
         cargo build -p litebox_runner_linux_userland --features audit_log"
    );
}

/// Find the litebox_broker binary.
fn find_broker() -> anyhow::Result<std::path::PathBuf> {
    if let Ok(path) = std::env::var("LITEBOX_BROKER") {
        let p = std::path::PathBuf::from(path);
        if p.exists() {
            return Ok(p);
        }
    }

    if let Ok(exe) = std::env::current_exe() {
        let sibling = exe
            .parent()
            .unwrap_or(std::path::Path::new("."))
            .join("litebox_broker");
        if sibling.exists() {
            return Ok(sibling);
        }
    }

    for candidate in [
        "/mnt/c/src/litebox/target/debug/litebox_broker",
        "./target/debug/litebox_broker",
    ] {
        let p = std::path::PathBuf::from(candidate);
        if p.exists() {
            return Ok(p);
        }
    }

    anyhow::bail!(
        "Could not find litebox_broker. \
         Set LITEBOX_BROKER env var or build it with: \
         cargo build -p litebox_broker"
    );
}

/// Managed broker process. Spawns the broker as a child and provides the IPC
/// socket path for the runner to connect to.
struct BrokerProcess {
    child: std::process::Child,
    socket_path: std::path::PathBuf,
}

impl BrokerProcess {
    /// Spawn the broker with the given rootfs and optional policy file.
    ///
    /// The broker listens on a Unix domain socket at a temporary path.
    /// The runner connects to it via `--network-broker`.
    fn spawn(rootfs: &std::path::Path, policy: Option<&std::path::Path>) -> anyhow::Result<Self> {
        let broker = find_broker()?;

        // Create a temporary socket path.
        let socket_path =
            std::env::temp_dir().join(format!("litebox-broker-{}.sock", std::process::id()));
        // Clean up any stale socket from a previous run.
        let _ = std::fs::remove_file(&socket_path);

        let mut cmd = std::process::Command::new(&broker);
        cmd.arg("--network-proxy-listen").arg(&socket_path);

        // Expose the rootfs directory for 9P access. The tar rootfs itself is
        // extracted by the runner, so we expose the rootfs's parent directory
        // (or the rootfs itself if it's a directory).
        if rootfs.is_dir() {
            cmd.arg("--root-dir").arg(rootfs);
        }

        cmd.arg("--rewrite-syscalls");

        if let Some(p) = policy {
            cmd.arg("--policy").arg(p);
        }

        let child = cmd
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit())
            .spawn()
            .map_err(|e| anyhow::anyhow!("Failed to spawn litebox_broker: {e}"))?;

        // Give the broker a moment to create the socket.
        for _ in 0..50 {
            if socket_path.exists() {
                return Ok(Self { child, socket_path });
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }

        Ok(Self { child, socket_path })
    }

    /// Get the IPC socket path for the runner's `--network-broker` flag.
    fn socket_path(&self) -> &std::path::Path {
        &self.socket_path
    }
}

impl Drop for BrokerProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

/// Build the base runner command with common flags.
fn runner_command(
    cli: &Cli,
    broker: Option<&BrokerProcess>,
) -> anyhow::Result<std::process::Command> {
    let runner = find_runner()?;
    let mut cmd = std::process::Command::new(&runner);
    cmd.arg("--unstable");
    cmd.arg("--initial-files").arg(&cli.rootfs);
    cmd.arg("--program-from-tar");

    // When a broker is running, connect the runner to it for network access.
    // Policy is enforced by the broker, not the runner.
    if let Some(b) = broker {
        cmd.arg("--network-broker")
            .arg(b.socket_path().to_str().unwrap_or(""));
    }

    if let Some(ref audit_log) = cli.audit_log {
        cmd.arg("--audit-log").arg(audit_log);
    }

    // Pass environment variables
    for kv in &cli.env {
        cmd.arg("--env").arg(kv);
    }
    // Always set basic environment if not provided
    let has = |prefix: &str| cli.env.iter().any(|e| e.starts_with(prefix));
    if !has("LD_LIBRARY_PATH=") {
        cmd.arg("--env")
            .arg("LD_LIBRARY_PATH=/lib64:/lib/x86_64-linux-gnu:/lib");
    }
    if !has("HOME=") {
        cmd.arg("--env").arg("HOME=/");
    }
    if !has("PATH=") {
        cmd.arg("--env").arg("PATH=/usr/bin:/bin");
    }
    if !has("TERM=") {
        cmd.arg("--env").arg("TERM=dumb");
    }

    cmd.arg("--");
    Ok(cmd)
}

/// Interactive shell mode. Launches a persistent bash session inside a single
/// sandbox. Shell state (cd, environment variables, etc.) persists across
/// commands. Uses `--noediting -s` and `TERM=dumb` to disable readline
/// (the sandbox reports stdin as a TTY, which would cause bash to enter
/// interactive/readline mode and hang).
fn interactive(cli: &Cli) -> anyhow::Result<()> {
    let broker = if cli.policy.is_some() {
        Some(BrokerProcess::spawn(&cli.rootfs, cli.policy.as_deref())?)
    } else {
        None
    };

    let mut cmd = runner_command(cli, broker.as_ref())?;

    // Launch bash in non-editing script mode:
    // --norc --noprofile: skip startup files
    // --noediting: disable readline (avoids hang on TTY stdin)
    // +m: disable job control (setpgid fails in the sandbox, breaking pipes)
    // -s: read commands from stdin
    cmd.args([
        &cli.shell,
        "--norc",
        "--noprofile",
        "--noediting",
        "+m",
        "-s",
    ]);

    // Pass stdin/stdout/stderr straight through. Audit events go directly
    // to the log file via the runner's --audit-log flag (no stderr capture).
    cmd.stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit());

    let status = cmd
        .status()
        .map_err(|e| anyhow::anyhow!("Failed to spawn litebox_runner_linux_userland: {e}"))?;

    // Broker is dropped here, which kills the broker process and cleans up.
    drop(broker);

    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
    Ok(())
}

/// Direct mode: run a single command.
fn direct(cli: &Cli) -> anyhow::Result<()> {
    let broker = if cli.policy.is_some() {
        Some(BrokerProcess::spawn(&cli.rootfs, cli.policy.as_deref())?)
    } else {
        None
    };

    let mut cmd = runner_command(cli, broker.as_ref())?;
    cmd.args(&cli.command);

    cmd.stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit());

    let status = cmd.status().map_err(|e| {
        anyhow::anyhow!(
            "Failed to spawn litebox_runner_linux_userland: {e}\n\
             Build it with: cargo build -p litebox_runner_linux_userland --features audit_log"
        )
    })?;

    drop(broker);

    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
    Ok(())
}
