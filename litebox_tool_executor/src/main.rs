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
#[command(group(clap::ArgGroup::new("policy_mode").required(true)))]
/// Execute Linux commands in a LiteBox sandbox.
struct Cli {
    /// Path to a .tar rootfs containing syscall-rewritten Linux binaries.
    #[arg(long, value_name = "PATH", value_hint = clap::ValueHint::FilePath)]
    rootfs: std::path::PathBuf,

    /// Path to a JSON policy file restricting guest operations.
    /// The broker enforces filesystem and network rules from this file.
    /// Mutually exclusive with `--record-baseline`.
    #[arg(long, value_name = "PATH", value_hint = clap::ValueHint::FilePath, group = "policy_mode")]
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

    /// Run VS Code Server inside the sandbox with stdio transport.
    /// The server protocol runs over stdin/stdout so VS Code's Remote
    /// extension can connect via the same pipe mechanism as docker exec.
    #[arg(long)]
    vscode_server: bool,

    /// SSH port for --vscode-server mode (default: 2222).
    /// Use a fixed port so the SSH config entry is stable across restarts.
    #[arg(long, default_value = "2222")]
    ssh_port: u16,

    /// Record a baseline: use the allow-all policy (no restrictions) so every
    /// operation succeeds while being fully audit-logged. Use this to
    /// capture the complete set of operations a workload needs,
    /// then generate a policy from the recording.
    /// Mutually exclusive with `--policy`.
    #[arg(long, group = "policy_mode")]
    record_baseline: bool,

    /// Forward a host TCP port to a guest port (HOST:GUEST_IP:GUEST_PORT).
    /// Can be specified multiple times. E.g. --forward-port 2223:10.0.0.2:22
    #[arg(long = "forward-port")]
    forward_port: Vec<String>,

    /// Run the litebox runner under gdbserver for remote debugging.
    /// The runner listens on the specified port (default: 9999) for GDB
    /// remote connections. Connect from the host with:
    ///   gdb -ex "target remote localhost:<port>" path/to/litebox_runner
    #[arg(long, value_name = "PORT", default_missing_value = "9999", num_args = 0..=1)]
    debug: Option<u16>,

    /// The command and arguments to run. Omit for interactive mode.
    #[arg(trailing_var_arg = true)]
    command: Vec<String>,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // When --debug is set, re-exec the entire tool_executor under gdbserver
    // so that both the broker and runner (spawned as children) are debuggable.
    // GDB can then use `set detach-on-fork off` to follow all processes.
    if let Some(port) = cli.debug {
        if std::env::var("_LITEBOX_UNDER_GDB").is_err() {
            let self_exe = std::env::current_exe()?;
            let args: Vec<String> = std::env::args().collect();
            eprintln!();
            eprintln!("=== GDB DEBUG MODE ===");
            eprintln!("  gdbserver listening on port {port}");
            eprintln!("  Connect from host with:");
            eprintln!(
                "    gdb -ex 'target remote localhost:{port}' {}",
                self_exe.display()
            );
            eprintln!("  Or use: bash dev_tools/gdb-connect.sh --port {port}");
            eprintln!("======================");
            eprintln!();
            let err = std::process::Command::new("gdbserver")
                .arg(format!(":{port}"))
                .arg(&self_exe)
                .args(&args[1..])
                .env("_LITEBOX_UNDER_GDB", "1")
                .status()?;
            std::process::exit(err.code().unwrap_or(1));
        }
    }

    if !cli.rootfs.exists() {
        anyhow::bail!(
            "Rootfs not found: {}\n\
             Build Docker image: docker build --target litebox-test -t litebox-test -f litebox_tool_executor/rootfs/Dockerfile .\n\
             Then run inside the container with --rootfs /",
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

    if cli.vscode_server {
        vscode_server(&cli, audit_log_file.as_deref())
    } else if cli.interactive {
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
    if let Ok(path) = std::env::var("LITEBOX_RUNNER") {
        let p = std::path::PathBuf::from(path);
        if p.exists() {
            return Ok(p);
        }
    }

    // Look next to our own binary — works for both Docker (/opt/litebox/)
    // and local development (target/debug/).
    if let Ok(exe) = std::env::current_exe() {
        let sibling = exe
            .parent()
            .unwrap_or(std::path::Path::new("."))
            .join("litebox_runner_linux_userland");
        if sibling.exists() {
            return Ok(sibling);
        }
    }

    anyhow::bail!(
        "Could not find litebox_runner_linux_userland. \
         Set LITEBOX_RUNNER env var or ensure it is built alongside litebox_tool_executor."
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

    anyhow::bail!(
        "Could not find litebox_broker. \
         Set LITEBOX_BROKER env var or ensure it is built alongside litebox_tool_executor."
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
        forward_ports: &[(u16, &str, u16)],
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

        // Always rewrite syscalls — the broker patches ELF binaries on-the-fly
        // when they're read over 9P. This handles both the base rootfs and any
        // binaries transferred at runtime (e.g., VS Code's localServerDownload).
        cmd.arg("--rewrite-syscalls");

        if let Some(p) = policy {
            cmd.arg("--policy").arg(p);
        }

        // Share the audit log file with the broker for unified event tracing.
        if let Some(p) = audit_log {
            cmd.arg("--audit-log").arg(p);
        }

        // Inbound TCP port forwards (e.g., host:2222 → guest sshd:22).
        for (host_port, guest_ip, guest_port) in forward_ports {
            cmd.arg("--forward-port")
                .arg(format!("{host_port}:{guest_ip}:{guest_port}"));
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

/// Spawn the broker, using the user-provided `--policy` file or no policy
/// for `--record-baseline` (the broker defaults to AllowAll when no policy
/// is given).
fn spawn_broker(
    cli: &Cli,
    audit_log_file: Option<&std::path::Path>,
    forward_ports: &[(u16, &str, u16)],
) -> anyhow::Result<BrokerProcess> {
    let policy_path = if cli.record_baseline {
        None
    } else {
        cli.policy.as_deref()
    };
    // Write broker logs to a .log file alongside the audit .jsonl files.
    let broker_log = audit_log_file.map(|p| p.with_extension("broker.log"));
    let broker = BrokerProcess::spawn(
        &cli.rootfs,
        policy_path,
        broker_log.as_deref(),
        audit_log_file,
        forward_ports,
    )?;
    Ok(broker)
}
fn runner_command(
    cli: &Cli,
    audit_log_file: Option<&std::path::Path>,
    broker: Option<&BrokerProcess>,
) -> anyhow::Result<std::process::Command> {
    let runner = find_runner()?;

    // --debug is now handled at the top of main() by wrapping the entire
    // tool_executor under gdbserver. The runner is started directly.
    let mut cmd = std::process::Command::new(&runner);

    cmd.arg("--unstable");

    let rootfs_is_dir = cli.rootfs.is_dir();

    if rootfs_is_dir {
        // Directory rootfs: program loads from 9P, not from a tar file.
        // The broker serves the directory; the runner connects via --nine-p-broker.
    } else {
        // Tar rootfs: runner extracts the tar and loads the program from it.
        cmd.arg("--initial-files").arg(&cli.rootfs);
        cmd.arg("--program-from-tar");
    }

    // When a broker is running, connect the runner to it for network access
    // and (for directory rootfs) 9P filesystem access.
    if let Some(b) = broker {
        let socket = b.socket_path().to_str().unwrap_or("");
        cmd.arg("--network-broker").arg(socket);
        if rootfs_is_dir {
            cmd.arg("--nine-p-broker").arg(socket);
        }
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
        cmd.arg("--env").arg("HOME=/root");
    }
    if !has("PATH=") {
        cmd.arg("--env").arg("PATH=/usr/local/bin:/usr/bin:/bin");
    }
    if !has("TERM=") {
        cmd.arg("--env").arg("TERM=dumb");
    }

    // Run as root inside the sandbox. The host process runs as a normal
    // user, but the guest should appear as root so sshd/dropbear can
    // authenticate users and manage sessions.
    cmd.args([
        "--guest-uid",
        "0",
        "--guest-euid",
        "0",
        "--guest-gid",
        "0",
        "--guest-egid",
        "0",
    ]);

    cmd.arg("--");

    // Reset signal handlers to SIG_DFL in the child process. The tool
    // executor (or its parent) may have installed handlers (e.g., Ctrl-C)
    // that the runner asserts must be at their defaults on startup.
    #[cfg(unix)]
    unsafe {
        use std::os::unix::process::CommandExt as _;
        cmd.pre_exec(|| {
            for sig in [
                libc::SIGINT,
                libc::SIGTERM,
                libc::SIGQUIT,
                libc::SIGHUP,
                libc::SIGPIPE,
            ] {
                libc::signal(sig, libc::SIG_DFL);
            }
            Ok(())
        });
    }

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
    let broker = spawn_broker(cli, audit_log_file, &[])?;

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

    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
    Ok(())
}

/// Direct mode: run a single command.
fn direct(cli: &Cli, audit_log_file: Option<&std::path::Path>) -> anyhow::Result<()> {
    // Parse --forward-port specs for direct mode.
    let forward_ports: Vec<(u16, &str, u16)> = cli
        .forward_port
        .iter()
        .filter_map(|spec| {
            let parts: Vec<&str> = spec.split(':').collect();
            if parts.len() == 3 {
                Some((
                    parts[0].parse::<u16>().ok()?,
                    parts[1],
                    parts[2].parse::<u16>().ok()?,
                ))
            } else {
                eprintln!(
                    "invalid --forward-port spec: {spec} (expected HOST:GUEST_IP:GUEST_PORT)"
                );
                None
            }
        })
        .collect();
    let broker = spawn_broker(cli, audit_log_file, &forward_ports)?;

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

/// VS Code Server mode: start OpenSSH sshd inside the sandbox.
///
/// Starts a broker with inbound TCP port forwarding (host:2222 → guest:22),
/// then runs ONE litebox runner with sshd as the init process. When VS Code
/// connects via Remote-SSH, sshd fork+execs bash, sftp-server, and VS Code
/// Server — all sharing one filesystem inside the sandbox.
///
/// Usage:
///   docker run --rm -p 2222:22 -v target/debug:/opt/litebox:ro litebox-vscode \
///     /opt/litebox/litebox_tool_executor --rootfs / --vscode-server
///   # then in VS Code: Remote-SSH → litebox (port 2222)
fn vscode_server(cli: &Cli, audit_log_file: Option<&std::path::Path>) -> anyhow::Result<()> {
    if !cli.rootfs.is_dir() {
        anyhow::bail!(
            "--vscode-server requires a directory rootfs (not a tar).\n\
             Use Docker: docker build --target litebox-vscode -t litebox-vscode -f litebox_tool_executor/rootfs/Dockerfile .\n\
             Then: docker run --rm -p 2222:22 -v target/debug:/opt/litebox:ro litebox-vscode /opt/litebox/litebox_tool_executor --rootfs / --vscode-server"
        );
    }

    // Auto-create an audit log directory if none was specified.
    // When LITEBOX_NO_AUDIT=1 is set, skip audit logging for performance testing.
    let auto_audit;
    let audit: Option<&std::path::Path> = if std::env::var("LITEBOX_NO_AUDIT").as_deref() == Ok("1")
    {
        None
    } else if let Some(p) = audit_log_file {
        Some(p)
    } else {
        let dir = std::env::temp_dir().join("litebox-vscode-server-logs");
        auto_audit = create_audit_log_file(&dir)?;
        Some(&auto_audit)
    };

    // The guest IP in the broker's virtual network.
    let guest_ip = "10.0.0.2";
    let ssh_port = cli.ssh_port;

    // Start the broker with inbound TCP forwarding for SSH only.
    // VS Code CLI loopback connections are handled by port registration +
    // cross-worker bridging in the broker.
    let forward_ports = [(ssh_port, guest_ip, 22u16)];
    let broker = spawn_broker(cli, audit, &forward_ports)?;

    // Build the runner command: dropbear SSH server
    // dropbear flags:
    //   -F  don't fork into background (foreground mode)
    //   -E  log to stderr
    //   -s  disable password login (empty passwords via -B instead)
    //   -B  allow blank passwords
    //   -R  create host keys if missing
    //   -p 22  listen on port 22 inside the sandbox
    let mut cmd = runner_command(cli, audit, Some(&broker))?;

    // Detect WSL2 IP for connection instructions.
    let wsl_ip = std::process::Command::new("hostname")
        .arg("-I")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().split_whitespace().next().unwrap_or("").to_string())
        .unwrap_or_default();

    let host_ip = if !wsl_ip.is_empty() && wsl_ip != "127.0.0.1" {
        &wsl_ip
    } else {
        "0.0.0.0"
    };

    eprintln!();
    eprintln!("==============================================");
    eprintln!("  LiteBox VS Code Server (dropbear SSH)");
    if cli.record_baseline {
        eprintln!("  *** RECORDING BASELINE (AllowAll policy) ***");
    }
    eprintln!("  dropbear inside sandbox on port 22");
    eprintln!("  Forwarding host:{ssh_port} → sandbox:22");
    eprintln!();
    eprintln!("  Add to ~/.ssh/config:");
    eprintln!("    Host litebox");
    eprintln!("        HostName {host_ip}");
    eprintln!("        Port {ssh_port}");
    eprintln!("        User root");
    eprintln!("        StrictHostKeyChecking no");
    eprintln!("        UserKnownHostsFile /dev/null");
    eprintln!();
    eprintln!("  Then in VS Code:");
    eprintln!("    Remote-SSH → Connect to Host → litebox");
    eprintln!();
    eprintln!("  Logs:");
    if let Some(audit) = audit {
        eprintln!("    Syscalls: {}", audit.display());
        eprintln!(
            "    Broker:   {}",
            audit.with_extension("broker.log").display()
        );
    } else {
        eprintln!("    Audit logging disabled (LITEBOX_NO_AUDIT=1)");
    }
    eprintln!("==============================================");
    eprintln!();

    // Pre-warm: run the code-server startup inside the dropbear sandbox
    // as a background process, so it shares the same PID namespace.
    // The dropbear init command becomes a shell script that starts both.
    let mut cmd = runner_command(cli, audit, Some(&broker))?;

    // Find the code-server path for pre-warming.
    let vscode_dir = cli.rootfs.join("root/.vscode-server/cli/servers");
    let prewarm_server = std::fs::read_dir(&vscode_dir).ok().and_then(|entries| {
        entries
            .filter_map(|e| {
                let e = e.ok()?;
                let name = e.file_name().to_string_lossy().to_string();
                if name.starts_with("Stable-") && e.path().join("server/bin/code-server").exists() {
                    let mtime = e.metadata().ok()?.modified().ok()?;
                    Some((mtime, name))
                } else {
                    None
                }
            })
            .max_by_key(|(mtime, _)| *mtime)
            .map(|(_, name)| name)
    });

    // Start dropbear SSH server. VS Code's install script will start the
    // code-server when it connects — no pre-warming needed since the
    // CLI and server are pre-installed in the Docker image.
    cmd.args(["/usr/sbin/dropbear", "-F", "-E", "-B", "-R", "-p", "22"]);

    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit());

    let status = cmd
        .status()
        .map_err(|e| anyhow::anyhow!("Failed to spawn litebox_runner_linux_userland: {e}"))?;

    drop(broker);

    if !status.success() {
        eprintln!("sshd exited with code {}", status.code().unwrap_or(-1));
        std::process::exit(status.code().unwrap_or(1));
    }
    Ok(())
}
