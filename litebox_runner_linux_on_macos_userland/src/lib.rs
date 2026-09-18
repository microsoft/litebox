// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Run AArch64 Linux PIE programs on an AArch64 macOS host.
#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

#[cfg(feature = "test-broker")]
use anyhow::Context as _;
use anyhow::{Result, bail};
use clap::Parser;
#[cfg(feature = "test-broker")]
use litebox_platform_macos_userland::MacosUserland4K;
use litebox_platform_macos_userland::{GuestAbi, set_guest_abi};
#[cfg(feature = "test-broker")]
use std::ffi::CString;
use std::path::PathBuf;

#[cfg(feature = "test-broker")]
mod test_broker;

#[derive(Parser, Debug)]
#[command(about = "AArch64 Linux runner for macOS; broker support is required")]
pub struct CliArgs {
    /// Program and its arguments; host path unless --program-from-tar is set.
    #[arg(required = true, trailing_var_arg = true, value_hint = clap::ValueHint::CommandWithArguments)]
    pub program_and_arguments: Vec<String>,
    /// Guest environment variable, KEY=VALUE.
    #[arg(long = "env")]
    pub environment_variables: Vec<String>,
    /// Forward the host environment.
    #[arg(long = "forward-env")]
    pub forward_environment_variables: bool,
    /// Enable unstable runner options.
    #[arg(short = 'Z', long = "unstable")]
    pub unstable: bool,
    /// Uncompressed tar containing the Linux interpreter, libraries and files.
    #[arg(long = "initial-files", value_name = "PATH_TO_TAR", value_hint = clap::ValueHint::FilePath,
          requires = "unstable", help_heading = "Unstable Options")]
    pub initial_files: Option<PathBuf>,
    /// Resolve the absolute program path within --initial-files.
    #[arg(long = "program-from-tar", requires_all = ["unstable", "initial_files"], help_heading = "Unstable Options")]
    pub program_from_tar: bool,
}

pub fn run(cli_args: CliArgs) -> Result<i32> {
    set_guest_abi(GuestAbi::Linux);
    tracing_subscriber::fmt()
        .with_timer(tracing_subscriber::fmt::time::uptime())
        .with_level(true)
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_env_var("LITEBOX_LOG")
                .from_env_lossy(),
        )
        .init();

    #[cfg(not(feature = "test-broker"))]
    {
        let _ = cli_args;
        bail!("filesystem startup on macOS requires broker support")
    }

    #[cfg(feature = "test-broker")]
    {
        let requested_program = cli_args
            .program_and_arguments
            .first()
            .context("missing program")?;
        if cli_args.program_from_tar && !requested_program.starts_with('/') {
            bail!("program path in --initial-files must be absolute, got: {requested_program}");
        }
        let platform = MacosUserland4K::new();
        let host_program =
            (!cli_args.program_from_tar).then(|| std::path::Path::new(requested_program));
        let setup = test_broker::setup(platform, cli_args.initial_files.as_deref(), host_program)?;
        let program_path = if cli_args.program_from_tar {
            requested_program.as_str()
        } else {
            setup.program_path.as_str()
        };
        let argv = cli_args
            .program_and_arguments
            .iter()
            .map(|value| CString::new(value.as_bytes()))
            .collect::<Result<Vec<_>, _>>()
            .context("NUL in program argument")?;
        let mut environment = cli_args.environment_variables;
        if cli_args.forward_environment_variables {
            environment.extend(std::env::vars().map(|(key, value)| format!("{key}={value}")));
        }
        let envp = environment
            .iter()
            .map(|value| CString::new(value.as_bytes()))
            .collect::<Result<Vec<_>, _>>()
            .context("NUL in environment entry")?;
        let shim = setup.builder.build();
        let program = shim
            .load_program(
                litebox_common_linux::TaskParams {
                    pid: setup.process_id,
                    ppid: 0,
                    uid: 1000,
                    euid: 1000,
                    gid: 1000,
                    egid: 1000,
                },
                program_path,
                argv,
                envp,
            )
            .context("loading Linux program")?;
        unsafe {
            litebox_platform_macos_userland::run_thread(
                program.entrypoints,
                &mut litebox_common_linux::PtRegs::default(),
            );
        }
        test_broker::flush_output(&setup.stdio)?;
        Ok(program.process.wait_for_unix_shell_exit_code())
    }
}
