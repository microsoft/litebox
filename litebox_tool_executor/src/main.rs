// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! CLI entrypoint for the LiteBox tool executor.
//!
//! Supports two modes:
//! - **Direct mode**: `litebox-tool-executor --rootfs rootfs.tar -- /usr/bin/bash -c "echo hello"`
//! - **Interactive REPL**: `litebox-tool-executor --rootfs rootfs.tar --interactive`
//!
//! Spawns `litebox_runner_linux_userland` as a subprocess for each command.

use clap::Parser as _;
use std::io::Write as _;

#[derive(clap::Parser, Debug)]
#[command(name = "litebox-tool-executor")]
/// Execute Linux commands in a LiteBox sandbox.
struct Cli {
    /// Path to a .tar rootfs containing syscall-rewritten Linux binaries.
    #[arg(long, value_name = "PATH", value_hint = clap::ValueHint::FilePath)]
    rootfs: std::path::PathBuf,

    /// Path to a JSON policy file restricting guest operations.
    #[arg(long, value_name = "PATH", value_hint = clap::ValueHint::FilePath)]
    policy: Option<std::path::PathBuf>,

    /// Run an interactive REPL shell (each line is a sandboxed command).
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

    /// The command and arguments to run. Omit for JSON pipe mode (stdin/stdout).
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
         cargo build -p litebox_runner_linux_userland --features audit_log,policy"
    );
}

/// Build the base runner command with common flags.
fn runner_command(cli: &Cli) -> anyhow::Result<std::process::Command> {
    let runner = find_runner()?;
    let mut cmd = std::process::Command::new(&runner);
    cmd.arg("--unstable");
    cmd.arg("--initial-files").arg(&cli.rootfs);
    cmd.arg("--program-from-tar");

    if let Some(ref policy) = cli.policy {
        cmd.arg("--policy").arg(policy);
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

    cmd.arg("--");
    Ok(cmd)
}

/// Interactive REPL mode. Each line runs in a fresh sandbox.
fn interactive(cli: &Cli) -> anyhow::Result<()> {
    eprintln!("LiteBox Sandbox Shell (each command runs in a fresh sandbox)");
    eprintln!("Type 'exit' to quit.");
    if let Some(ref log_path) = cli.audit_log {
        eprintln!("Audit log: {}", log_path.display());
    }
    eprintln!();

    let stdin = std::io::stdin();
    loop {
        eprint!("sandbox$ ");
        std::io::stderr().flush()?;

        let mut line = String::new();
        let n = stdin.read_line(&mut line)?;
        if n == 0 {
            break; // EOF
        }
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if line == "exit" {
            break;
        }

        let mut cmd = runner_command(cli)?;
        cmd.args([&cli.shell, "--norc", "--noprofile", "-c", line]);

        // Inherit stdin (null) and stdout. For stderr:
        // - If --audit-log is set, capture stderr and write it to the file
        //   (the runner emits audit events as JSON on stderr by default).
        // - Otherwise, inherit stderr so the user sees everything.
        cmd.stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::inherit());

        if cli.audit_log.is_some() {
            cmd.stderr(std::process::Stdio::piped());
        } else {
            cmd.stderr(std::process::Stdio::inherit());
        }

        match cmd.output() {
            Ok(out) => {
                if let Some(ref log_path) = cli.audit_log {
                    if let Ok(mut f) = std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(log_path)
                    {
                        let _ = std::io::Write::write_all(&mut f, &out.stderr);
                    }
                }
                if !out.status.success() {
                    let code = out.status.code().unwrap_or(-1);
                    if code == 124 {
                        eprintln!("[timed out]");
                    } else {
                        eprintln!("[exit code: {code}]");
                    }
                }
            }
            Err(e) => {
                eprintln!("[error: {e}]");
            }
        }
    }

    Ok(())
}

/// Direct mode: run a single command.
fn direct(cli: &Cli) -> anyhow::Result<()> {
    let mut cmd = runner_command(cli)?;
    cmd.args(&cli.command);

    cmd.stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit());

    let status = cmd.status().map_err(|e| {
        anyhow::anyhow!(
            "Failed to spawn litebox_runner_linux_userland: {e}\n\
             Build it with: cargo build -p litebox_runner_linux_userland --features audit_log,policy"
        )
    })?;

    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
    Ok(())
}
