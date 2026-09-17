// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Run static, position-independent AArch64 Mach-O programs on Apple Silicon.
#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use anyhow::{Context as _, Result, bail};
use clap::Parser;
use litebox_common_macos::TaskParams;
use litebox_platform_macos_userland::{GuestAbi, MacosUserland, set_guest_abi};
#[cfg(not(feature = "test-stdio"))]
use litebox_shim_macos::MacosShimBuilder;
use std::ffi::CString;

#[derive(Parser, Debug)]
#[command(about = "Run AOT-rewritten static AArch64 Mach-O programs (no dyld or Mach traps)")]
pub struct CliArgs {
    /// Host path of a Mach-O processed by litebox_syscall_rewriter, followed by guest arguments.
    #[arg(required = true, trailing_var_arg = true, value_hint = clap::ValueHint::CommandWithArguments)]
    pub program_and_arguments: Vec<String>,
    /// Guest environment entry (KEY=VALUE). Host environment is not forwarded.
    #[arg(long = "env")]
    pub environment_variables: Vec<String>,
}

#[cfg(feature = "test-stdio")]
mod test_broker;

pub fn run(cli_args: CliArgs) -> Result<i32> {
    set_guest_abi(GuestAbi::Darwin);
    let Some(path) = cli_args.program_and_arguments.first() else {
        bail!("missing program");
    };
    let data = std::fs::read(path).with_context(|| format!("reading {path}"))?;
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
    #[cfg(not(feature = "test-stdio"))]
    let builder = MacosShimBuilder::new(platform);
    #[cfg(feature = "test-stdio")]
    let (builder, stdio) = test_broker::setup(platform)?;
    let program = builder
        .build()
        .load_program(TaskParams::default(), &data, argv, envp)
        .context("loading static Mach-O")?;
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
    #[cfg(feature = "test-stdio")]
    test_broker::flush_output(&stdio)?;
    process
        .exit_status()
        .context("guest stopped without an exit status")
}
