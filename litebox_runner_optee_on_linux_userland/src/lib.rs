// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use anyhow::{Context, Result};
use clap::Parser;
use litebox_common_optee::{TeeUuid, UteeEntryFunc, UteeParamOwned};
use litebox_platform_multiplex::Platform;
use litebox_shim_optee::session::allocate_session_id;
use std::path::{Path, PathBuf};

mod tests;

#[derive(Parser, Debug)]
pub struct CliArgs {
    /// ldelf
    #[arg(required = true, value_hint = clap::ValueHint::ExecutablePath)]
    pub ldelf: String,
    /// Trusted Application (TA)
    #[arg(required = true, value_hint = clap::ValueHint::ExecutablePath)]
    pub program: String,
    /// JSON-formatted command sequence to pass to the TA
    #[arg(required = true, value_hint = clap::ValueHint::FilePath)]
    pub command_sequence: String,
    /// Allow using unstable options
    #[arg(short = 'Z', long = "unstable")]
    pub unstable: bool,
    /// Apply syscall-rewriter to the ELF file before running it
    ///
    /// This is meant as a convenience feature; real deployments would likely prefer ahead-of-time
    /// rewrite things to amortize costs.
    #[arg(
        long = "rewrite-syscalls",
        requires = "unstable",
        help_heading = "Unstable Options"
    )]
    pub rewrite_syscalls: bool,
    /// Choice of interception backend
    #[arg(
        value_enum,
        long = "interception-backend",
        requires = "unstable",
        help_heading = "Unstable Options",
        default_value = "rewriter"
    )]
    pub interception_backend: InterceptionBackend,
}

/// Backends supported for intercepting syscalls
#[non_exhaustive]
#[derive(Debug, Clone, clap::ValueEnum)]
pub enum InterceptionBackend {
    /// Use seccomp-based syscall interception
    Seccomp,
    /// Depend purely on rewriten syscalls to intercept them
    Rewriter,
}

fn rewrite_program_bytes(data: &[u8], path: &Path) -> Result<Vec<u8>> {
    let mut skipped_addrs = Vec::new();
    match litebox_syscall_rewriter::hook_syscalls_in_elf(data, None, &mut skipped_addrs) {
        Ok(rewritten) => {
            if !skipped_addrs.is_empty() {
                eprintln!(
                    "warning: {} has {} unpatchable syscall instruction(s) at {:?}",
                    path.display(),
                    skipped_addrs.len(),
                    skipped_addrs,
                );
            }
            Ok(rewritten)
        }
        Err(litebox_syscall_rewriter::Error::UnsupportedBunExecutable) => anyhow::bail!(
            "{} is a Bun-packaged executable, and this runner requires a LiteBox trampoline to load it; Bun-packaged executables are unsupported here",
            path.display()
        ),
        Err(e) => Err(e).with_context(|| format!("failed to rewrite {}", path.display())),
    }
}

fn load_program_data(path: &Path, rewrite_syscalls: bool) -> Result<Vec<u8>> {
    let data = std::fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    if rewrite_syscalls {
        rewrite_program_bytes(&data, path)
    } else {
        Ok(data)
    }
}

/// Test OP-TEE TAs with LiteBox on unmodified Linux
///
/// # Panics
///
/// Can panic if any particulars of the environment are not set up as expected. Ideally, would not
/// panic. If it does actually panic, then ping the authors of LiteBox, and likely a better error
/// message could be thrown instead.
pub fn run(cli_args: CliArgs) -> Result<()> {
    let ldelf = PathBuf::from(&cli_args.ldelf);
    let ldelf_data = load_program_data(&ldelf, cli_args.rewrite_syscalls)?;
    let prog = PathBuf::from(&cli_args.program);
    let prog_data = load_program_data(&prog, cli_args.rewrite_syscalls)?;

    // TODO(jb): Clean up platform initialization once we have https://github.com/MSRSSP/litebox/issues/24
    //
    // TODO: We also need to pick the type of syscall interception based on whether we want
    // systrap/sigsys interception, or binary rewriting interception. Currently
    // `litebox_platform_linux_userland` does not provide a way to pick between the two.
    let platform = Platform::new(None);
    litebox_platform_multiplex::set_platform(platform);
    let shim_builder = litebox_shim_optee::OpteeShimBuilder::new();
    let _litebox = shim_builder.litebox();
    let shim = shim_builder.build();
    match cli_args.interception_backend {
        InterceptionBackend::Seccomp => platform.enable_seccomp_based_syscall_interception(),
        InterceptionBackend::Rewriter => {}
    }

    if cli_args.command_sequence.is_empty() {
        run_ta_with_default_commands(&shim, ldelf_data.as_slice(), prog_data.as_slice());
    } else {
        tests::run_ta_with_test_commands(
            &shim,
            ldelf_data.as_slice(),
            prog_data.as_slice(),
            cli_args.program.as_str(),
            &PathBuf::from(&cli_args.command_sequence),
        );
    }
    Ok(())
}

/// This function simply opens and closes a session to the TA to verify that
/// it can be loaded and run. Note that an OP-TEE TA does nothing without
/// a client invoking commands on it.
fn run_ta_with_default_commands(
    shim: &litebox_shim_optee::OpteeShim,
    ldelf_bin: &[u8],
    ta_bin: &[u8],
) {
    for func_id in [UteeEntryFunc::OpenSession, UteeEntryFunc::CloseSession] {
        let params = [const { UteeParamOwned::None }; UteeParamOwned::TEE_NUM_PARAMS];

        if func_id == UteeEntryFunc::OpenSession {
            let loaded_program = shim
                .load_ldelf(
                    ldelf_bin,
                    TeeUuid::default(),
                    Some(ta_bin),
                    None,
                    allocate_session_id().unwrap(),
                )
                .map_err(|_| {
                    panic!("Failed to load ldelf");
                })
                .unwrap();
            let entrypoints = loaded_program.entrypoints.as_ref().unwrap();
            unsafe {
                litebox_platform_linux_userland::run_thread_ref(
                    entrypoints,
                    &mut litebox_common_linux::ExecutionContext::default(),
                );
            }

            // In OP-TEE TA, each command invocation is like (re)starting the TA with a new stack with
            // loaded binary and heap. In that sense, we can create (and destroy) a stack
            // for each command freely.
            let _ = entrypoints
                .load_ta_context(params.as_slice(), None, func_id as u32, None)
                .map_err(|_| {
                    panic!("Failed to load TA context");
                });
            unsafe {
                litebox_platform_linux_userland::reenter_thread(
                    entrypoints,
                    &mut litebox_common_linux::ExecutionContext::default(),
                );
            }
        } else if func_id == UteeEntryFunc::CloseSession {
        }
    }
}
