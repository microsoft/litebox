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
use std::io::Read as _;

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

    /// Directory to write audit log files (JSON lines). Each session creates
    /// a new timestamped file, e.g. `audit-dir/2026-04-08T12-34-56.jsonl`.
    #[arg(long = "audit-log", value_name = "DIR", value_hint = clap::ValueHint::DirPath)]
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

    // Resolve audit log: create directory and generate a timestamped file path.
    let audit_log_file = if let Some(ref dir) = cli.audit_log {
        Some(create_audit_log_file(dir)?)
    } else {
        None
    };

    // Print binary build times for diagnostics.
    print_build_info(audit_log_file.as_deref());

    if cli.interactive {
        interactive(&cli, audit_log_file.as_deref())
    } else {
        direct(&cli, audit_log_file.as_deref())
    }
}

/// Create a timestamped audit log file inside the given directory.
/// Returns the full path to the new file.
fn create_audit_log_file(dir: &std::path::Path) -> anyhow::Result<std::path::PathBuf> {
    std::fs::create_dir_all(dir).map_err(|e| {
        anyhow::anyhow!(
            "Could not create audit log directory {}: {e}",
            dir.display()
        )
    })?;

    // Generate a timestamp-based filename: YYYY-MM-DDTHH-MM-SS.jsonl
    // Use seconds since epoch as a fallback-safe approach.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    // Convert to approximate human-readable (good enough for filenames).
    let days = secs / 86400;
    let years = 1970 + days / 365; // approximate
    let day_of_year = days % 365;
    let month = day_of_year / 30 + 1;
    let day = day_of_year % 30 + 1;
    let time_of_day = secs % 86400;
    let hour = time_of_day / 3600;
    let minute = (time_of_day % 3600) / 60;
    let second = time_of_day % 60;
    let filename =
        format!("{years:04}-{month:02}-{day:02}T{hour:02}-{minute:02}-{second:02}.jsonl");

    let path = dir.join(filename);
    eprintln!("Audit log: {}", path.display());
    Ok(path)
}

/// Print build timestamps of this binary, the runner, and the broker for diagnostics.
/// Writes to both stderr (visible in terminal) and the audit log file (if provided).
fn print_build_info(audit_log_file: Option<&std::path::Path>) {
    let mut lines = Vec::new();

    if let Ok(exe) = std::env::current_exe() {
        if let Ok(meta) = std::fs::metadata(&exe) {
            if let Ok(modified) = meta.modified() {
                let age = std::time::SystemTime::now()
                    .duration_since(modified)
                    .unwrap_or_default();
                lines.push(format!(
                    "Tool executor: {} (built {}s ago)",
                    exe.display(),
                    age.as_secs()
                ));
            }
        }
    }
    if let Ok(runner) = find_runner() {
        if let Ok(meta) = std::fs::metadata(&runner) {
            if let Ok(modified) = meta.modified() {
                let age = std::time::SystemTime::now()
                    .duration_since(modified)
                    .unwrap_or_default();
                lines.push(format!(
                    "Runner: {} (built {}s ago)",
                    runner.display(),
                    age.as_secs()
                ));
            }
        }
    }
    if let Ok(broker) = find_broker() {
        if let Ok(meta) = std::fs::metadata(&broker) {
            if let Ok(modified) = meta.modified() {
                let age = std::time::SystemTime::now()
                    .duration_since(modified)
                    .unwrap_or_default();
                lines.push(format!(
                    "Broker: {} (built {}s ago)",
                    broker.display(),
                    age.as_secs()
                ));
            }
        }
    }

    for line in &lines {
        eprintln!("{line}");
    }

    // Also write to the audit log file so the tail script can show them.
    if let Some(path) = audit_log_file {
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            use std::io::Write;
            for line in &lines {
                let _ = writeln!(f, "# {line}");
            }
        }
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
    /// If `log_file` is provided, broker stdout/stderr go there instead of /dev/null.
    fn spawn(
        rootfs: &std::path::Path,
        policy: Option<&std::path::Path>,
        log_file: Option<&std::path::Path>,
        audit_log: Option<&std::path::Path>,
    ) -> anyhow::Result<Self> {
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

        // Share the audit log file with the broker for unified event tracing.
        if let Some(p) = audit_log {
            cmd.arg("--audit-log").arg(p);
        }

        let child = cmd
            .stdin(std::process::Stdio::null())
            .stdout(if let Some(p) = log_file {
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(p)
                    .map(std::process::Stdio::from)
                    .unwrap_or(std::process::Stdio::null())
            } else {
                std::process::Stdio::null()
            })
            .stderr(if let Some(p) = log_file {
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(p)
                    .map(std::process::Stdio::from)
                    .unwrap_or(std::process::Stdio::null())
            } else {
                std::process::Stdio::null()
            })
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

/// Default sandbox policy applied when no `--policy` file is specified.
///
/// - Filesystem: deny access to secrets (`.ssh`, `passwd`, `shadow`, private keys)
/// - Network: deny all outbound connections
const DEFAULT_POLICY: &str = r#"{
    "filesystem": {
        "allow_read": [],
        "allow_write": ["/tmp/**", "/workspace/**"],
        "deny": ["**/.ssh/**", "**/passwd", "**/shadow", "**/id_rsa*", "**/id_ed25519*"]
    },
    "network": {
        "deny_all": true,
        "allow_connect": []
    }
}"#;

/// Write the default policy to a temporary file and return its path.
fn write_default_policy() -> anyhow::Result<TempFile> {
    let path = std::env::temp_dir().join(format!(
        "litebox-default-policy-{}.json",
        std::process::id()
    ));
    std::fs::write(&path, DEFAULT_POLICY)?;
    Ok(TempFile(path))
}

/// A file that is deleted when dropped.
struct TempFile(std::path::PathBuf);

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Spawn the broker, using the user-provided policy or the built-in default.
fn spawn_broker(
    cli: &Cli,
    audit_log_file: Option<&std::path::Path>,
) -> anyhow::Result<(BrokerProcess, Option<TempFile>)> {
    let (policy_path, temp_policy) = if let Some(ref p) = cli.policy {
        (p.clone(), None)
    } else {
        let tmp = write_default_policy()?;
        let path = tmp.0.clone();
        (path, Some(tmp))
    };
    // Write broker logs to a .log file alongside the audit .jsonl files.
    let broker_log = audit_log_file.map(|p| p.with_extension("broker.log"));
    let broker = BrokerProcess::spawn(
        &cli.rootfs,
        Some(&policy_path),
        broker_log.as_deref(),
        audit_log_file,
    )?;
    Ok((broker, temp_policy))
}
fn runner_command(
    cli: &Cli,
    audit_log_file: Option<&std::path::Path>,
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
    if let Some(audit_path) = audit_log_file {
        cmd.arg("--audit-log").arg(audit_path);
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
/// commands.
///
/// Stdin is piped through a bridge thread so the runner's stdin is NOT a TTY.
/// This prevents bash from enabling job control (which breaks pipelines in
/// the sandbox because setpgid fails for the session-leader init process).
fn interactive(cli: &Cli, audit_log_file: Option<&std::path::Path>) -> anyhow::Result<()> {
    let (broker, _temp_policy) = spawn_broker(cli, audit_log_file)?;

    let mut cmd = runner_command(cli, audit_log_file, Some(&broker))?;

    // Launch bash in non-editing script mode:
    // --norc --noprofile: skip startup files
    // --noediting: disable readline
    // -s: read commands from stdin
    cmd.args([&cli.shell, "--norc", "--noprofile", "--noediting", "-s"]);

    // Pipe stdin so the runner sees a pipe, not a TTY. This makes bash
    // enter non-interactive mode and skip job control entirely.
    cmd.stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit());

    let mut child = cmd
        .spawn()
        .map_err(|e| anyhow::anyhow!("Failed to spawn litebox_runner_linux_userland: {e}"))?;

    // Bridge host stdin to the child's piped stdin in a background thread.
    let mut child_stdin = child.stdin.take().unwrap();
    let stdin_thread = std::thread::spawn(move || {
        let mut host_stdin = std::io::stdin().lock();
        let mut buf = [0u8; 4096];
        loop {
            match host_stdin.read(&mut buf) {
                Ok(0) => break, // EOF
                Ok(n) => {
                    if std::io::Write::write_all(&mut child_stdin, &buf[..n]).is_err() {
                        break; // child closed stdin
                    }
                }
                Err(_) => break,
            }
        }
    });

    let status = child
        .wait()
        .map_err(|e| anyhow::anyhow!("Failed to wait for litebox_runner_linux_userland: {e}"))?;

    // stdin thread will exit when the child closes its end or host stdin hits EOF.
    let _ = stdin_thread.join();

    // Clean up the broker process.
    drop(broker);
    // Temp policy file cleaned up when _temp_policy drops.

    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
    Ok(())
}

/// Direct mode: run a single command.
fn direct(cli: &Cli, audit_log_file: Option<&std::path::Path>) -> anyhow::Result<()> {
    let (broker, _temp_policy) = spawn_broker(cli, audit_log_file)?;

    let mut cmd = runner_command(cli, audit_log_file, Some(&broker))?;
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
