// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Run AArch64 Linux PIE programs on an AArch64 macOS host with a separate broker.
#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use anyhow::{Context as _, Result, bail};
use clap::Parser;
use litebox_broker_local_userland as broker;
use litebox_platform_macos_userland::{MacosUserland4K as Platform, with_guest_signals_blocked};
use std::{ffi::CString, path::PathBuf};

#[derive(Parser, Debug)]
#[command(about = "AArch64 Linux runner for macOS; a separate broker is required")]
pub struct CliArgs {
    /// Absolute program path in the broker-owned filesystem, followed by arguments.
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
    /// Broker-supplied Unix socket path for the control channel.
    #[arg(
        long = "broker-control-channel",
        value_name = "PATH",
        hide = true,
        requires = "unstable",
        help_heading = "Unstable Options"
    )]
    pub broker_control_channel: Option<PathBuf>,
}

/// Connects to the trusted broker and runs the guest. This does not install a
/// Seatbelt profile; production launchers must confine this process separately.
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
    let path = cli_args
        .program_and_arguments
        .first()
        .context("a guest program is required")?;
    if !path.starts_with('/') {
        bail!("program path must be absolute in the broker filesystem");
    }
    let control = cli_args
        .broker_control_channel
        .as_deref()
        .context("macOS requires --broker-control-channel from a separate broker")?;
    let platform = Platform::new();
    let broker::BrokerConnection {
        local,
        notifications,
        coordinator,
    } = with_guest_signals_blocked(|| broker::connect(control))??;
    let litebox = litebox::LiteBox::new_with_broker_local(platform, local);
    coordinator.install_dispatch(litebox.broker_failure_dispatcher());
    with_guest_signals_blocked(|| {
        broker::start_notification_receiver(
            notifications,
            coordinator,
            litebox.broker_notification_dispatcher(),
        )
    })??;
    let shim = litebox_shim_linux::LinuxShimBuilder::new_with_litebox(platform, litebox).build();
    let argv = cli_args
        .program_and_arguments
        .iter()
        .map(|arg| CString::new(arg.as_bytes()))
        .collect::<Result<Vec<_>, _>>()?;
    let mut environment = cli_args.environment_variables;
    if cli_args.forward_environment_variables {
        environment.extend(std::env::vars().map(|(key, value)| format!("{key}={value}")));
    }
    let envp = environment
        .iter()
        .map(|value| CString::new(value.as_bytes()))
        .collect::<Result<Vec<_>, _>>()?;
    let task = litebox_common_linux::TaskParams {
        pid: i32::try_from(std::process::id())?,
        // Guest identity is virtual, not the broker's host identity.
        ppid: 0,
        uid: 1000,
        euid: 1000,
        gid: 1000,
        egid: 1000,
    };
    let program = shim.load_program(task, path, argv, envp)?;
    // SAFETY: the loader prepared the guest entrypoints and mapped guest image.
    unsafe {
        litebox_platform_macos_userland::run_thread(
            program.entrypoints,
            &mut litebox_common_linux::PtRegs::default(),
        );
    }
    Ok(program.process.wait_for_unix_shell_exit_code())
}
