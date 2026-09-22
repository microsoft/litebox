// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Run static, position-independent AArch64 Mach-O programs on Apple Silicon.
#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use anyhow::{Context as _, Result, bail};
use clap::Parser;
use litebox_common_macos::TaskParams;
use litebox_platform_macos_userland::{GuestAbi, MacosUserland, set_guest_abi};
#[cfg(not(feature = "test-broker"))]
use litebox_shim_macos::MacosShimBuilder;
#[cfg(feature = "test-broker")]
use std::path::PathBuf;
use std::{ffi::CString, io::Read as _};

#[derive(Parser, Debug)]
#[command(about = "Run self-contained static AArch64 Mach-O programs (no dyld)")]
pub struct CliArgs {
    /// Host path of a thin or universal Mach-O, followed by guest arguments.
    /// Accepts raw or AOT-rewritten static images. No host filesystem passthrough,
    /// dynamic linking, or shared-cache support.
    #[arg(required = true, trailing_var_arg = true, value_hint = clap::ValueHint::CommandWithArguments)]
    pub program_and_arguments: Vec<String>,
    /// Guest environment entry (KEY=VALUE). Host environment is not forwarded.
    #[arg(long = "env")]
    pub environment_variables: Vec<String>,
    /// Host Mach-O exposed at /mmap-image for mmap rewriting tests.
    #[cfg(feature = "test-broker")]
    #[arg(long, hide = true, value_hint = clap::ValueHint::FilePath)]
    pub test_mmap_image: Option<PathBuf>,
}

#[cfg(feature = "test-broker")]
mod test_broker;

pub fn run(cli_args: CliArgs) -> Result<i32> {
    set_guest_abi(GuestAbi::Darwin);
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
    let program = program.context("loading Mach-O")?;
    let litebox_shim_macos::LoadedProgram {
        entrypoints,
        process,
        mut initial_ctx,
    } = program;
    // SAFETY: the loader owns valid mappings and has finalized Darwin gates;
    // entrypoints retain those mappings until guest execution stops.
    unsafe {
        litebox_platform_macos_userland::run_thread(entrypoints, &mut initial_ctx);
    }
    #[cfg(feature = "test-broker")]
    test_broker::flush_output(&stdio)?;
    process
        .exit_status()
        .context("guest stopped without an exit status")
}
