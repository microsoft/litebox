// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Runner for [`litebox_syscall_rewriter`]

use clap::Parser;
use clap::ValueEnum;
use std::io::Read as _;
use std::io::Write as _;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::PathBuf;

/// The AArch64 host anchor to rewrite an ELF's gates against -- mirrors
/// [`litebox_syscall_rewriter::Host`], which is not itself `ValueEnum` (it
/// lives in a `no_std` crate). Ignored for x86-64/PE input. Getting this
/// wrong is not cosmetic: a `Linux`-anchored rewrite run on a macOS guest
/// reads a live thread-pointer value from the wrong register (`TPIDR_EL0`,
/// which the host does not preserve) and crashes the guest on its first
/// reschedule, misleadingly far from the actual cause -- see
/// [`litebox_syscall_rewriter::Host::MacOs`]'s own doc comment.
#[derive(Clone, Copy, Debug, ValueEnum)]
enum HostArg {
    /// The host preserves `TPIDR_EL0` across a context switch.
    Linux,
    /// The host is macOS/Darwin (Apple Silicon): `TPIDR_EL0` does not survive
    /// a context switch, so gates anchor on `TPIDRRO_EL0` instead.
    Macos,
}

impl From<HostArg> for litebox_syscall_rewriter::Host {
    fn from(value: HostArg) -> Self {
        match value {
            HostArg::Linux => litebox_syscall_rewriter::Host::Linux,
            HostArg::Macos => litebox_syscall_rewriter::Host::MacOs,
        }
    }
}

/// Rewrite ELF files to hook syscalls, or PE files to hook syscalls and change GS TEB accesses to FS.
#[derive(Parser, Debug)]
struct CliArgs {
    /// Path to input binary
    input_binary: PathBuf,
    /// Path to output the generated binary (default = <INPUT_BINARY>.hooked)
    #[arg(short = 'o', long = "output")]
    output_binary: Option<PathBuf>,
    /// Absolute address to set in the trampoline (default = 0)
    #[arg(long)]
    trampoline_addr: Option<u64>,
    /// AArch64 ELF host to anchor the rewritten gates against (ignored for
    /// x86-64/PE input). Defaults to `linux`; pass `macos` when the rewritten
    /// binary will run under a macOS-hosted LiteBox runner instead.
    #[arg(long, value_enum, default_value_t = HostArg::Linux)]
    host: HostArg,
}

fn copy_file_permissions(
    input_file: &std::fs::File,
    output_file: &std::fs::File,
) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        output_file.set_permissions(std::fs::Permissions::from_mode(
            input_file.metadata()?.mode(),
        ))?;
    }
    #[cfg(windows)]
    {
        let input_metadata = input_file.metadata()?;
        let perms = input_metadata.permissions();
        output_file.set_permissions(perms)?;
    }
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let cli_args = CliArgs::parse();
    let mut input_binary = std::fs::File::open(&cli_args.input_binary)?;
    let mut input_binary_bytes = vec![];
    input_binary.read_to_end(&mut input_binary_bytes)?;
    let output_binary = litebox_syscall_rewriter::rewrite_binary_for_host(
        &input_binary_bytes,
        cli_args.trampoline_addr,
        cli_args.host.into(),
    )?;
    let output_path = cli_args.output_binary.unwrap_or_else(|| {
        cli_args.input_binary.with_file_name(
            cli_args
                .input_binary
                .file_name()
                .unwrap()
                .to_string_lossy()
                .into_owned()
                + ".hooked",
        )
    });
    let mut file = std::fs::File::create(output_path)?;
    copy_file_permissions(&input_binary, &file)?;
    file.write_all(&output_binary)?;
    Ok(())
}
