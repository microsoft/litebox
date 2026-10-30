// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Run AArch64 Linux PIE programs on an AArch64 macOS host.
//!
//! `litebox-broker-userland` launches this runner with `--unstable --broker-control-channel`.
//! Without a broker channel, only the development-only `test-broker` feature can run a program,
//! against an in-process broker fixture.
#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use anyhow::{Context as _, Result, bail};
use clap::Parser;
use litebox_broker_local_userland as broker;
use litebox_common_linux::program_startup::{LinuxProcessStartup, LinuxProgramStartup};
use litebox_common_linux::signal::SigSet;
use litebox_platform_macos_userland::{GuestAbi, MacosUserland4K, set_guest_abi};
use std::ffi::CString;
use std::path::{Path, PathBuf};

#[cfg(feature = "test-broker")]
mod test_broker;

// Like the Linux runner, use a stable non-root guest identity instead of mirroring the host user.
const DEFAULT_GUEST_UID: u32 = 1000;
const DEFAULT_GUEST_GID: u32 = 1000;

#[derive(Parser, Debug)]
#[command(about = "AArch64 Linux runner for macOS; broker support is required")]
pub struct CliArgs {
    /// Program and its arguments.
    ///
    /// With a broker, the program path must be absolute and refer to a file in the broker-owned
    /// file system. With the in-process test broker, it is a host path unless --program-from-tar
    /// is set.
    #[arg(trailing_var_arg = true, value_hint = clap::ValueHint::CommandWithArguments)]
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
    /// Broker-supplied Unix socket path for the local control channel.
    #[arg(
        long = "broker-control-channel",
        value_name = "PATH",
        value_hint = clap::ValueHint::FilePath,
        hide = true,
        requires = "unstable",
        help_heading = "Unstable Options"
    )]
    pub broker_control_channel: Option<PathBuf>,
    /// Uncompressed tar containing the Linux interpreter, libraries and files, for the in-process
    /// test broker.
    #[arg(long = "initial-files", value_name = "PATH_TO_TAR", value_hint = clap::ValueHint::FilePath,
          requires = "unstable", conflicts_with = "broker_control_channel", help_heading = "Unstable Options")]
    pub initial_files: Option<PathBuf>,
    /// Resolve the absolute program path within --initial-files.
    #[arg(long = "program-from-tar", requires_all = ["unstable", "initial_files"], help_heading = "Unstable Options")]
    pub program_from_tar: bool,
}

pub fn run(mut cli_args: CliArgs) -> Result<i32> {
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

    if let Some(control_socket_path) = cli_args.broker_control_channel.take() {
        return run_with_broker(&control_socket_path, &cli_args);
    }

    #[cfg(not(feature = "test-broker"))]
    {
        let _ = cli_args;
        bail!("the macOS runner requires --broker-control-channel from litebox-broker-userland")
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
        let (argv, envp) = command_line_strings(&cli_args)?;
        let shim = setup.builder.build();
        let program = shim
            .load_program(
                litebox_common_linux::TaskParams {
                    pid: setup.process_id,
                    uid: 1000,
                    euid: 1000,
                    gid: 1000,
                    egid: 1000,
                    blocked_signals: litebox_common_linux::signal::SigSet::empty(),
                    ignored_signals: litebox_common_linux::signal::SigSet::empty(),
                    inherited_fds: None,
                    cwd: None,
                    umask: None,
                    #[cfg(target_arch = "aarch64")]
                    sve_vl_inherit: false,
                },
                setup.initial_thread,
                program_path,
                argv,
                envp,
            )
            .context("loading Linux program")?;
        // SAFETY: the loader owns valid mappings and has finalized Linux gates;
        // entrypoints retain those mappings until guest execution stops.
        unsafe {
            litebox_platform_macos_userland::run_thread(
                program.entrypoints,
                &mut litebox_common_linux::PtRegs::default(),
            );
        }
        let exit_code = program.process.wait_for_unix_shell_exit_code();
        test_broker::flush_output(&setup.stdio)?;
        Ok(exit_code)
    }
}

/// Runs the program the broker at `control_socket_path` starts, or the command-line program if
/// the broker supplies none, and returns its shell exit code.
fn run_with_broker(control_socket_path: &Path, cli_args: &CliArgs) -> Result<i32> {
    let (connection, startup) =
        litebox_platform_macos_userland::with_guest_signals_blocked(|| {
            broker::connect(control_socket_path)
        })?;
    let platform = MacosUserland4K::new();
    let broker::BrokerConnection {
        local,
        notifications,
        coordinator,
    } = connection;
    let (litebox, process_id, initial_thread) =
        litebox::LiteBox::new_process_with_broker_local(platform, local);
    let process_id = i32::try_from(process_id.0).context("process ID does not fit Linux pid_t")?;
    coordinator.install_dispatch(litebox.broker_failure_dispatcher());
    litebox_platform_macos_userland::with_guest_signals_blocked(|| {
        broker::start_notification_receiver(
            notifications,
            coordinator,
            litebox.broker_notification_dispatcher(),
        )
    })?;
    let shim =
        litebox_shim_linux::LinuxShimBuilder::new_with_litebox(platform, litebox, process_id)
            .build();
    let startup = startup
        .map(|startup| LinuxProcessStartup::decode(&startup.payload))
        .transpose()
        .context("invalid child Linux process startup")?;
    let (task_params, program_path, argv, envp) = match startup {
        Some(LinuxProcessStartup::Fork(_)) => {
            bail!("forked children cannot continue on macOS, which has no process images")
        }
        Some(LinuxProcessStartup::Program(startup)) => {
            let LinuxProgramStartup {
                uid,
                euid,
                gid,
                egid,
                blocked_signals,
                ignored_signals,
                umask,
                sve_vl_inherit,
                path,
                cwd,
                argv,
                envp,
                inherited_fds,
            } = startup;
            (
                litebox_common_linux::TaskParams {
                    pid: process_id,
                    uid,
                    euid,
                    gid,
                    egid,
                    blocked_signals,
                    ignored_signals,
                    inherited_fds: Some(inherited_fds),
                    cwd: Some(cwd),
                    umask: Some(umask),
                    sve_vl_inherit,
                },
                path,
                argv,
                envp,
            )
        }
        None => {
            let program_path = cli_args
                .program_and_arguments
                .first()
                .context("program path missing")?
                .clone();
            if !program_path.starts_with('/') {
                bail!("program path must be absolute (e.g., /usr/bin/ls), got: {program_path}");
            }
            let (argv, envp) = command_line_strings(cli_args)?;
            (
                litebox_common_linux::TaskParams {
                    pid: process_id,
                    uid: DEFAULT_GUEST_UID,
                    euid: DEFAULT_GUEST_UID,
                    gid: DEFAULT_GUEST_GID,
                    egid: DEFAULT_GUEST_GID,
                    blocked_signals: SigSet::empty(),
                    // Host dispositions use Darwin signal numbers, so none are inherited.
                    ignored_signals: SigSet::empty(),
                    inherited_fds: None,
                    cwd: None,
                    umask: None,
                    sve_vl_inherit: false,
                },
                program_path,
                argv,
                envp,
            )
        }
    };
    let program = shim
        .load_program(task_params, initial_thread, &program_path, argv, envp)
        .context("loading Linux program")?;
    // SAFETY: the loader owns valid mappings and has finalized Linux gates;
    // entrypoints retain those mappings until guest execution stops.
    unsafe {
        litebox_platform_macos_userland::run_thread(
            program.entrypoints,
            &mut litebox_common_linux::PtRegs::default(),
        );
    }
    // The shell exit code cannot tell a signal death from an exit with code 128+signal, so report
    // the guest status for the parent to observe. If the report fails, the broker falls back to
    // the runner's host exit status.
    let _ = shim
        .litebox()
        .report_exit_status(program.process.wait_for_exit_status());
    Ok(program.process.wait_for_unix_shell_exit_code())
}

/// Returns the command-line program arguments and guest environment, including the host
/// environment if forwarded, as C strings.
fn command_line_strings(cli_args: &CliArgs) -> Result<(Vec<CString>, Vec<CString>)> {
    let argv = cli_args
        .program_and_arguments
        .iter()
        .map(|value| CString::new(value.as_bytes()))
        .collect::<Result<Vec<_>, _>>()
        .context("NUL in program argument")?;
    let mut environment = cli_args.environment_variables.clone();
    if cli_args.forward_environment_variables {
        environment.extend(std::env::vars().map(|(key, value)| format!("{key}={value}")));
    }
    let envp = environment
        .iter()
        .map(|value| CString::new(value.as_bytes()))
        .collect::<Result<Vec<_>, _>>()
        .context("NUL in environment entry")?;
    Ok((argv, envp))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn child_runner_cli_does_not_require_root_program() {
        let args = CliArgs::try_parse_from([
            "runner",
            "--unstable",
            "--broker-control-channel",
            "/tmp/broker.sock",
        ])
        .unwrap();

        assert_eq!(args.program_and_arguments, [] as [String; 0]);
    }
}
