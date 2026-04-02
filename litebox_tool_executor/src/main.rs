// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! CLI entrypoint for the LiteBox tool executor.
//!
//! Supports three modes:
//! - **Direct mode**: `litebox-tool-executor --rootfs rootfs.tar -- /bin/busybox echo hello`
//! - **Interactive REPL**: `litebox-tool-executor --rootfs rootfs.tar --interactive`
//! - **JSON pipe mode**: reads a [`ToolRequest`] from stdin (when no command given and not interactive)

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
fn main() -> anyhow::Result<()> {
    use clap::Parser as _;
    use std::io::Write as _;

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
        eprintln!("Type 'exit' to quit. Commands are executed via busybox.");
        if let Some(ref log_path) = cli.audit_log {
            eprintln!("Audit log: {}", log_path.display());
        }
        eprintln!();

        let exe = std::env::current_exe()?;
        let stdin = std::io::stdin();
        loop {
            print!("/ $ ");
            std::io::stdout().flush()?;

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

            // Spawn a child process: litebox_tool_executor --rootfs <tar> /bin/busybox sh -c <line>
            // The command goes as a single argv element — no shell escaping needed.
            let mut child_args = vec![
                "--rootfs".to_string(),
                cli.rootfs.to_str().unwrap_or_default().to_string(),
            ];
            if let Some(ref policy_path) = cli.policy {
                child_args.push("--policy".to_string());
                child_args.push(policy_path.to_str().unwrap_or_default().to_string());
            }
            child_args.extend([
                "/bin/busybox".to_string(),
                "sh".to_string(),
                "-c".to_string(),
                line.to_string(),
            ]);

            // Capture the child's output and print it ourselves, rather than
            // relying on inherited stdio (which doesn't work reliably when our
            // own stdout is a pipe on Windows).
            let output = std::process::Command::new(&exe)
                .args(&child_args)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .output();
            match output {
                Ok(out) => {
                    use std::io::Write as _;
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
        // Return normally so all destructors run and stdio buffers flush.
        // process::exit() skips this and can lose piped output on Windows.
        if result.exit_code != 0 {
            anyhow::bail!("guest exited with code {}", result.exit_code);
        }
    }
    Ok(())
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
/// Console control handler that ignores Ctrl+C in the REPL parent process.
/// Child processes handle their own termination; we don't want Ctrl+C from
/// VS Code's terminal management to kill the REPL.
unsafe extern "system" fn ctrl_handler(ctrl_type: u32) -> i32 {
    // CTRL_C_EVENT = 0, CTRL_BREAK_EVENT = 1
    if ctrl_type <= 1 {
        1 // TRUE = handled, don't terminate
    } else {
        0 // FALSE = not handled, use default behavior (terminate for CLOSE etc.)
    }
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
/// Load a sandbox policy from a JSON file.
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

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
#[derive(clap::Parser, Debug)]
#[command(name = "litebox-tool-executor")]
/// Execute Linux commands in a LiteBox sandbox on Windows.
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
    /// Path to write the audit log (JSON lines). In interactive mode, child
    /// stderr (audit events) is appended here instead of being discarded.
    #[arg(long = "audit-log", value_name = "PATH", value_hint = clap::ValueHint::FilePath)]
    audit_log: Option<std::path::PathBuf>,
    /// Environment variables passed to the program (`KEY=VALUE`; repeatable).
    #[arg(long = "env")]
    env: Vec<String>,
    /// The command and arguments to run. Omit for JSON pipe mode (stdin/stdout).
    #[arg(trailing_var_arg = true)]
    command: Vec<String>,
}

#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
fn main() {
    eprintln!("This program is only supported on Windows x86_64");
    std::process::exit(1);
}
