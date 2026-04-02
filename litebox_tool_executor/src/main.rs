// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! CLI entrypoint for the LiteBox tool executor.
//!
//! Supports two modes:
//! - **Direct mode**: `litebox-tool-executor --rootfs rootfs.tar -- /bin/ls -la`
//! - **JSON pipe mode**: reads a [`ToolRequest`] from stdin, writes a [`ToolResult`] to stdout.

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
fn main() -> anyhow::Result<()> {
    use clap::Parser as _;

    let cli = Cli::parse();
    let tar_data = std::fs::read(&cli.rootfs).map_err(|e| {
        anyhow::anyhow!("Could not read rootfs tar at {}: {e}", cli.rootfs.display())
    })?;

    if cli.command.is_empty() {
        // JSON pipe mode: read ToolRequest from stdin.
        let request: litebox_tool_executor::protocol::ToolRequest =
            serde_json::from_reader(std::io::stdin().lock())?;
        let result = litebox_tool_executor::execute(tar_data, &request)?;
        serde_json::to_writer(std::io::stdout().lock(), &result)?;
        println!();
    } else {
        // Direct CLI mode.
        let request = litebox_tool_executor::protocol::ToolRequest {
            command: cli.command,
            env: cli.env,
            files: std::collections::HashMap::new(),
            timeout_secs: None,
        };
        let result = litebox_tool_executor::execute(tar_data, &request)?;
        std::process::exit(result.exit_code);
    }
    Ok(())
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
#[derive(clap::Parser, Debug)]
#[command(name = "litebox-tool-executor")]
/// Execute Linux commands in a LiteBox sandbox on Windows.
struct Cli {
    /// Path to a .tar rootfs containing syscall-rewritten Linux binaries.
    #[arg(long, value_name = "PATH", value_hint = clap::ValueHint::FilePath)]
    rootfs: std::path::PathBuf,
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
