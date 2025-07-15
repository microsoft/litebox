//! Runner for [`litebox_syscall_rewriter`]

use clap::Parser;
use std::io::Read as _;
use std::io::Write as _;
use std::os::unix::fs::MetadataExt as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;

/// Rewrite ELF files to hook syscalls
#[derive(Parser, Debug)]
struct CliArgs {
    /// Path to input ELF binary
    input_binary: PathBuf,
    /// Path to output the generated binary (default = <INPUT_BINARY>.hooked)
    #[arg(short = 'o', long = "output")]
    output_binary: Option<PathBuf>,
    /// Absolute address to set in the trampoline (default = 0)
    #[arg(long)]
    trampoline_addr: Option<usize>,
}

fn main() -> anyhow::Result<()> {
    let cli_args = CliArgs::parse();
    let mut input_binary = std::fs::File::open(&cli_args.input_binary)?;
    let mut input_binary_bytes = vec![];
    input_binary.read_to_end(&mut input_binary_bytes)?;
    let output_binary = litebox_syscall_rewriter::hook_syscalls_in_elf(
        &input_binary_bytes,
        cli_args.trampoline_addr,
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
    file.set_permissions(std::fs::Permissions::from_mode(
        input_binary.metadata()?.mode(),
    ))?;
    file.write_all(&output_binary)?;
    Ok(())
}
