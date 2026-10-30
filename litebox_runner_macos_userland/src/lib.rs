// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Run static, position-independent AArch64 Mach-O programs on Apple Silicon.
//!
//! Without a broker, the program is loaded from host bytes and the guest has no file system or
//! standard streams. With `--unstable --broker-control-channel`, as `litebox-broker-userland`
//! launches it, the program is loaded from the broker-owned file system and the guest's standard
//! streams are the broker's.
#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use anyhow::{Context as _, Result, anyhow, bail};
use clap::Parser;
use litebox_broker_local_userland as broker;
use litebox_broker_protocol::fs::{FileAccessMode, FileMode, FileOpenFlags, FileUser};
use litebox_common_macos::TaskParams;
use litebox_platform_macos_userland::{GuestAbi, MacosUserland, set_guest_abi};
use litebox_shim_macos::{LoadedProgram, MacosShimBuilder};
use std::path::{Path, PathBuf};
use std::{ffi::CString, io::Read as _};

#[derive(Parser, Debug)]
#[command(about = "Run self-contained static AArch64 Mach-O programs (no dyld)")]
pub struct CliArgs {
    /// Path of a thin or universal Mach-O, followed by guest arguments.
    /// Accepts raw or AOT-rewritten static images. No dynamic linking or shared-cache support.
    ///
    /// With a broker, the path must be absolute and refer to a file in the broker-owned file
    /// system; otherwise it is a host path and the guest has no file system.
    #[arg(trailing_var_arg = true, value_hint = clap::ValueHint::CommandWithArguments)]
    pub program_and_arguments: Vec<String>,
    /// Guest environment entry (KEY=VALUE). Host environment is not forwarded.
    #[arg(long = "env")]
    pub environment_variables: Vec<String>,
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
    /// Host Mach-O exposed at /mmap-image for mmap rewriting tests.
    #[cfg(feature = "test-broker")]
    #[arg(long, hide = true, value_hint = clap::ValueHint::FilePath, conflicts_with = "broker_control_channel")]
    pub test_mmap_image: Option<PathBuf>,
}

#[cfg(feature = "test-broker")]
mod test_broker;

pub fn run(cli_args: CliArgs) -> Result<i32> {
    set_guest_abi(GuestAbi::Darwin);
    if let Some(control_socket_path) = &cli_args.broker_control_channel {
        return run_with_broker(control_socket_path, &cli_args);
    }
    let Some(path) = cli_args.program_and_arguments.first() else {
        bail!("missing program");
    };
    // Bound allocation even if the file grows; one extra byte detects oversized input.
    let mut data = Vec::new();
    std::fs::File::open(path)
        .with_context(|| format!("opening {path}"))?
        .take(litebox_common_macos::loader::MAX_IMAGE_SIZE as u64 + 1)
        .read_to_end(&mut data)
        .with_context(|| format!("reading {path}"))?;
    if data.len() > litebox_common_macos::loader::MAX_IMAGE_SIZE {
        bail!("Mach-O file larger than 256 MiB: {path}");
    }
    let (argv, envp) = command_line_strings(&cli_args)?;
    let platform = MacosUserland::new();
    #[cfg(not(feature = "test-broker"))]
    let builder = MacosShimBuilder::new(platform);
    #[cfg(feature = "test-broker")]
    let (builder, stdio) = {
        let mmap_image = cli_args
            .test_mmap_image
            .as_deref()
            .map(std::fs::read)
            .transpose()
            .context("reading mmap test image")?;
        test_broker::setup(platform, data, mmap_image.as_deref())?
    };
    #[cfg(feature = "test-broker")]
    let program = builder
        .build()
        .load_program(TaskParams::default(), "/executable", argv, envp);
    #[cfg(not(feature = "test-broker"))]
    let program =
        builder
            .build()
            .load_program_from_bytes(TaskParams::default(), path, &data, argv, envp);
    let status = run_program(program.context("loading Mach-O")?)?;
    #[cfg(feature = "test-broker")]
    test_broker::flush_output(&stdio)?;
    Ok(status)
}

/// Runs the command-line program from the file system of the broker at `control_socket_path`
/// and returns its exit status.
///
/// The broker observes that status as this runner's exit status; the guest's own report is not
/// sent because a Darwin guest is always a root process, which has no parent to collect it.
fn run_with_broker(control_socket_path: &Path, cli_args: &CliArgs) -> Result<i32> {
    let (connection, startup) =
        litebox_platform_macos_userland::with_guest_signals_blocked(|| {
            broker::connect(control_socket_path)
        })?;
    if startup.is_some() {
        bail!("the Darwin shim cannot start a child process");
    }
    let Some(path) = cli_args.program_and_arguments.first() else {
        bail!("missing program");
    };
    if !path.starts_with('/') {
        bail!("program path must be absolute in the broker file system, got: {path}");
    }
    let (argv, envp) = command_line_strings(cli_args)?;
    let platform = MacosUserland::new();
    let broker::BrokerConnection {
        local,
        notifications,
        coordinator,
    } = connection;
    let litebox = litebox::LiteBox::new_with_broker_local(platform, local);
    coordinator.install_dispatch(litebox.broker_failure_dispatcher());
    litebox_platform_macos_userland::with_guest_signals_blocked(|| {
        broker::start_notification_receiver(
            notifications,
            coordinator,
            litebox.broker_notification_dispatcher(),
        )
    })?;
    let mut builder = MacosShimBuilder::new_with_litebox(platform, litebox);
    inherit_standard_streams(&mut builder)?;
    let program = builder
        .build()
        .load_program(TaskParams::default(), path, argv, envp)
        .context("loading Mach-O")?;
    run_program(program)
}

/// Runs `program` until it exits and returns its exit status.
fn run_program(program: LoadedProgram<MacosUserland>) -> Result<i32> {
    let LoadedProgram {
        entrypoints,
        process,
        mut initial_ctx,
    } = program;
    // SAFETY: the loader owns valid mappings and has finalized Darwin gates;
    // entrypoints retain those mappings until guest execution stops.
    unsafe {
        litebox_platform_macos_userland::run_thread(entrypoints, &mut initial_ctx);
    }
    process
        .exit_status()
        .context("guest stopped without an exit status")
}

/// Opens the broker file system's `/dev` standard streams as the guest's descriptors 0, 1 and 2.
pub(crate) fn inherit_standard_streams(
    builder: &mut MacosShimBuilder<MacosUserland>,
) -> Result<()> {
    let mut context = litebox::fs::Context::new();
    context.set_acting_user(FileUser::ROOT);
    for (path, access) in [
        ("/dev/stdin", FileAccessMode::ReadOnly),
        ("/dev/stdout", FileAccessMode::WriteOnly),
        ("/dev/stderr", FileAccessMode::WriteOnly),
    ] {
        let fd = builder
            .litebox()
            .open_file(
                &context,
                path,
                access,
                FileOpenFlags::NONE,
                FileMode::empty(),
            )
            .with_context(|| format!("opening standard stream {path}"))?;
        builder
            .inherit_file(fd)
            .map_err(|error| anyhow!("inheriting {path}: {error}"))?;
    }
    Ok(())
}

/// Returns the command-line program arguments and guest environment as C strings.
fn command_line_strings(cli_args: &CliArgs) -> Result<(Vec<CString>, Vec<CString>)> {
    let argv = cli_args
        .program_and_arguments
        .iter()
        .map(|s| CString::new(s.as_bytes()))
        .collect::<Result<Vec<_>, _>>()
        .context("NUL in program argument")?;
    let envp = cli_args
        .environment_variables
        .iter()
        .map(|s| CString::new(s.as_bytes()))
        .collect::<Result<Vec<_>, _>>()
        .context("NUL in environment entry")?;
    Ok((argv, envp))
}
