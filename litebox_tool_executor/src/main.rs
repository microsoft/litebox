// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! CLI entrypoint for the LiteBox tool executor.
//!
//! Supports three modes:
//! - **Direct mode**: `litebox-tool-executor --rootfs rootfs.tar -- /usr/bin/bash -c "echo hello"`
//! - **Interactive REPL**: `litebox-tool-executor --rootfs rootfs.tar --interactive`
//! - **JSON pipe mode**: reads a [`ToolRequest`] from stdin (when no command given and not interactive)
//!
//! On Windows the sandbox runs in-process via the Windows userland platform.
//! On Linux the sandbox spawns `litebox_runner_linux_userland` as a subprocess.

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

// ---------------------------------------------------------------------------
// Linux: spawn litebox_runner_linux_userland as a subprocess
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
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
        linux_interactive(&cli)
    } else if cli.command.is_empty() {
        linux_json_pipe(&cli)
    } else {
        linux_direct(&cli)
    }
}

/// Find the litebox_runner_linux_userland binary.
#[cfg(target_os = "linux")]
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
#[cfg(target_os = "linux")]
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

/// Interactive REPL mode on Linux. Each line runs in a fresh sandbox.
#[cfg(target_os = "linux")]
fn linux_interactive(cli: &Cli) -> anyhow::Result<()> {
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

/// Direct mode on Linux: run a single command.
#[cfg(target_os = "linux")]
fn linux_direct(cli: &Cli) -> anyhow::Result<()> {
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

/// JSON pipe mode on Linux: read ToolRequest from stdin, execute, write ToolResult.
#[cfg(target_os = "linux")]
fn linux_json_pipe(cli: &Cli) -> anyhow::Result<()> {
    let request: litebox_tool_executor::protocol::ToolRequest =
        serde_json::from_reader(std::io::stdin().lock())?;

    let mut cmd = runner_command(cli)?;
    // Use the shell to run the command
    let shell_cmd = request.command.join(" ");
    cmd.args([&cli.shell, "--norc", "--noprofile", "-c", &shell_cmd]);

    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    let output = cmd.output().map_err(|e| {
        anyhow::anyhow!("Failed to spawn litebox_runner_linux_userland: {e}")
    })?;

    let result = litebox_tool_executor::protocol::ToolResult {
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        exit_code: output.status.code().unwrap_or(-1),
        audit_log: Vec::new(),
        timed_out: false,
    };
    serde_json::to_writer(std::io::stdout().lock(), &result)?;
    println!();
    Ok(())
}

// ---------------------------------------------------------------------------
// Windows: in-process sandbox via litebox core APIs
// ---------------------------------------------------------------------------

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let tar_data = std::fs::read(&cli.rootfs).map_err(|e| {
        anyhow::anyhow!("Could not read rootfs tar at {}: {e}", cli.rootfs.display())
    })?;

    if cli.interactive {
        // Interactive REPL mode: read lines from stdin, execute each as a
        // separate child process of this executor. This avoids the singleton
        // platform limitation (each child gets its own process) and also means
        // the command string is passed via argv with no shell quoting issues.
        //
        // Install a Ctrl+C handler so the REPL survives when VS Code sends
        // Ctrl+C to the terminal after a command completes. Without this,
        // the REPL exits with STATUS_CONTROL_C_EXIT (0xC000013A).
        unsafe {
            windows_sys::Win32::System::Console::SetConsoleCtrlHandler(
                Some(ctrl_handler),
                1, // TRUE = add handler
            );
        }

        eprintln!("LiteBox Sandbox Shell (each command runs in a fresh sandbox)");
        eprintln!("Type 'exit' to quit.");
        if let Some(ref log_path) = cli.audit_log {
            eprintln!("Audit log: {}", log_path.display());
        }
        eprintln!();

        let exe = std::env::current_exe()?;
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

            let mut child_args = vec![
                "--rootfs".to_string(),
                cli.rootfs.to_str().unwrap_or_default().to_string(),
            ];
            if let Some(ref policy_path) = cli.policy {
                child_args.push("--policy".to_string());
                child_args.push(policy_path.to_str().unwrap_or_default().to_string());
            }
            child_args.extend([
                cli.shell.clone(),
                "-c".to_string(),
                line.to_string(),
            ]);

            let output = std::process::Command::new(&exe)
                .args(&child_args)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .output();
            match output {
                Ok(out) => {
                    let _ = std::io::stdout().write_all(&out.stdout);
                    let _ = std::io::stdout().flush();
                    // Append child stderr (audit log) to file if configured.
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
                        eprintln!("[exit code: {}]", out.status.code().unwrap_or(-1));
                    }
                }
                Err(e) => {
                    eprintln!("[error: {e}]");
                }
                _ => {}
            }
        }
    } else if cli.command.is_empty() {
        // JSON pipe mode: read ToolRequest from stdin.
        let policy = cli.policy.map(|path| load_policy(&path)).transpose()?;
        let request: litebox_tool_executor::protocol::ToolRequest =
            serde_json::from_reader(std::io::stdin().lock())?;
        let result = litebox_tool_executor::execute(tar_data, &request, policy)?;
        serde_json::to_writer(std::io::stdout().lock(), &result)?;
        println!();
    } else {
        // Direct CLI mode.
        let policy = cli.policy.map(|path| load_policy(&path)).transpose()?;
        let request = litebox_tool_executor::protocol::ToolRequest {
            command: cli.command,
            env: cli.env,
            files: std::collections::HashMap::new(),
            timeout_secs: None,
        };
        let result = litebox_tool_executor::execute(tar_data, &request, policy)?;
        if result.exit_code != 0 {
            anyhow::bail!("guest exited with code {}", result.exit_code);
        }
    }
    Ok(())
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
/// Console control handler that ignores Ctrl+C in the REPL parent process.
unsafe extern "system" fn ctrl_handler(ctrl_type: u32) -> i32 {
    if ctrl_type <= 1 {
        1 // TRUE = handled, don't terminate
    } else {
        0
    }
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
fn load_policy(
    path: &std::path::Path,
) -> anyhow::Result<litebox_shim_linux::policy::SandboxPolicy> {
    #[derive(serde::Deserialize)]
    struct PolicyFile {
        #[serde(default)]
        filesystem: FsPolicyFile,
        #[serde(default)]
        network: NetworkPolicyFile,
        #[serde(default)]
        process: ProcessPolicyFile,
    }
    #[derive(serde::Deserialize, Default)]
    struct FsPolicyFile {
        #[serde(default)]
        allow_read: Vec<String>,
        #[serde(default)]
        allow_write: Vec<String>,
        #[serde(default)]
        deny: Vec<String>,
    }
    #[derive(serde::Deserialize, Default)]
    struct NetworkPolicyFile {
        #[serde(default)]
        deny_all: bool,
        #[serde(default)]
        allow_connect: Vec<String>,
    }
    #[derive(serde::Deserialize, Default)]
    struct ProcessPolicyFile {
        #[serde(default)]
        allow_exec: Vec<String>,
    }

    let data = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("Could not read policy file {}: {e}", path.display()))?;
    let pf: PolicyFile = serde_json::from_str(&data)
        .map_err(|e| anyhow::anyhow!("Invalid policy JSON in {}: {e}", path.display()))?;

    Ok(litebox_shim_linux::policy::SandboxPolicy {
        filesystem: litebox_shim_linux::policy::FsPolicy {
            allow_read: pf.filesystem.allow_read,
            allow_write: pf.filesystem.allow_write,
            deny: pf.filesystem.deny,
        },
        network: litebox_shim_linux::policy::NetworkPolicy {
            deny_all: pf.network.deny_all,
            allow_connect: pf.network.allow_connect,
        },
        process: litebox_shim_linux::policy::ProcessPolicy {
            allow_exec: pf.process.allow_exec,
        },
    })
}

// ---------------------------------------------------------------------------
// Unsupported platforms
// ---------------------------------------------------------------------------

#[cfg(not(any(
    target_os = "linux",
    all(target_os = "windows", target_arch = "x86_64")
)))]
fn main() {
    eprintln!("litebox-tool-executor is only supported on Linux x86_64 and Windows x86_64");
    std::process::exit(1);
}
