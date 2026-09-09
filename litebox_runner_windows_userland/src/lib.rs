// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Restrict this crate to only work on Windows. For now, we are restricting this to only x86-64
// Windows, but we _may_ allow for more in the future, if we find it useful to do so.
#![cfg(all(target_os = "windows", target_arch = "x86_64"))]

extern crate alloc;

use anyhow::{Context as _, Result};
use clap::Parser;
use litebox_broker_local_userland as broker;
use litebox_platform_windows_userland::WindowsUserland;
use std::path::PathBuf;

/// Runs a Windows PE program with LiteBox on unmodified Windows and returns its exit code.
///
/// The program binary and any initial filesystem contents must be provided inside a tar archive via
/// `--initial-files`. The program path refers to a path inside the tar archive.
#[derive(Parser, Debug)]
pub struct CliArgs {
    /// The program and arguments passed to it (e.g., `/app/program.exe --help`).
    ///
    /// The program path refers to a path inside the tar archive provided via `--initial-files`.
    #[arg(required = true, trailing_var_arg = true, value_hint = clap::ValueHint::CommandWithArguments)]
    pub program_and_arguments: Vec<String>,
    /// Environment variables passed to the program (`K=V` pairs; can be invoked multiple times).
    #[arg(long = "env")]
    pub environment_variables: Vec<String>,
    /// Forward the existing environment variables.
    #[arg(long = "forward-env")]
    pub forward_environment_variables: bool,
    /// Allow using unstable options.
    #[arg(short = 'Z', long = "unstable")]
    pub unstable: bool,
    /// Broker-supplied Windows named-pipe path for the local control channel.
    #[arg(
        long = "broker-control-channel",
        value_name = "PIPE_NAME",
        hide = true,
        requires = "unstable",
        help_heading = "Unstable Options"
    )]
    pub broker_control_channel: Option<std::ffi::OsString>,
    /// Tar archive containing the program and its runtime files.
    ///
    /// This may be omitted when the broker was configured with `--fs-initial-files`.
    #[arg(long = "initial-files", value_name = "PATH_TO_TAR", value_hint = clap::ValueHint::FilePath)]
    pub initial_files: Option<PathBuf>,
}

/// Run Windows PE programs with LiteBox on unmodified Windows.
///
/// # Panics
///
/// Panics if the initial in-memory file system fails to create `/tmp` — those
/// operations cannot fail against a freshly-constructed file system.
pub fn run(cli_args: CliArgs) -> Result<i32> {
    tracing_subscriber::fmt()
        .with_timer(tracing_subscriber::fmt::time::uptime())
        .with_level(true)
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_env_var("LITEBOX_LOG")
                .from_env_lossy(),
        )
        .init();

    let platform = WindowsUserland::new();
    let control_pipe = cli_args
        .broker_control_channel
        .as_deref()
        .context("file operations require --broker-control-channel")?;
    let broker::BrokerConnection {
        local,
        notifications,
    } = broker::connect(control_pipe)?;
    let litebox = litebox::LiteBox::new_with_broker_local(platform, local);
    broker::start_notification_receiver(
        notifications,
        litebox.broker_notification_dispatcher(),
        litebox.broker_failure_dispatcher(),
    )?;
    let shim_builder =
        litebox_shim_windows::WindowsShimBuilder::new_with_litebox(platform, litebox);

    let (program_path, program_args) = cli_args
        .program_and_arguments
        .split_first()
        .context("program path missing — clap should have required at least one argument")?;

    let shim = shim_builder.build();
    let argv = std::iter::once(program_path.as_str())
        .chain(program_args.iter().map(String::as_str))
        .map(to_cstring)
        .collect::<Result<Vec<_>>>()
        .context("argv contained an interior NUL byte")?;
    let mut envp = cli_args
        .environment_variables
        .iter()
        .map(|s| to_cstring(s))
        .collect::<Result<Vec<_>>>()
        .context("--env value contained an interior NUL byte")?;
    if cli_args.forward_environment_variables {
        for (key, value) in std::env::vars() {
            envp.push(
                to_cstring(&format!("{key}={value}"))
                    .context("forwarded environment variable contained an interior NUL byte")?,
            );
        }
    }

    let program = shim
        .load_program(program_path, argv, envp)
        .context("failed to load Windows PE program")?;
    // SAFETY: `WindowsShimEntrypoints::init` populates `rip`/`rsp`/`eflags` inside
    // `run_thread` before the initial guest thread executes, so the `PtRegs::default()`
    // we hand in is fully initialized before any guest instruction runs.
    unsafe {
        litebox_platform_windows_userland::run_thread(
            program.entrypoints,
            &mut litebox_common_linux::PtRegs::default(),
        );
    }
    Ok(program.process.wait())
}

fn to_cstring(s: &str) -> Result<std::ffi::CString> {
    std::ffi::CString::new(s.as_bytes()).map_err(Into::into)
}
