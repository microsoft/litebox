use anyhow::{Result, anyhow};
use clap::Parser;
use litebox_platform_multiplex::Platform;
use std::path::PathBuf;

// TODO(jb): Remove all the `unwrap`s from this

/// Run Linux programs with LiteBox on unmodified Linux
#[derive(Parser, Debug)]
struct CliArgs {
    /// The program and arguments passed to it (e.g., `python3 --version`)
    #[arg(required = true, trailing_var_arg = true, value_hint = clap::ValueHint::CommandWithArguments)]
    program_and_arguments: Vec<String>,
    /// Allow using unstable options
    #[arg(short = 'Z', long = "unstable")]
    unstable: bool,
    /// Pre-fill files into the initial file system state
    // TODO: Might want to extend this to support full directories at some point?
    #[arg(long = "insert-file", value_hint = clap::ValueHint::FilePath,
          requires = "unstable", help_heading = "Unstable Options")]
    insert_files: Vec<PathBuf>,
    /// Pre-fill the files in this tar file into the initial file system state
    #[arg(long = "initial-files", value_name = "PATH_TO_TAR", value_hint = clap::ValueHint::FilePath,
          requires = "unstable", help_heading = "Unstable Options")]
    initial_files: Option<PathBuf>,
}

fn main() -> Result<()> {
    let cli_args = CliArgs::parse();

    if !cli_args.insert_files.is_empty() {
        unimplemented!(
            "this should (hopefully soon) have a nicer interface to support loading in files"
        )
    }

    // TODO(jb): Clean up platform initialization once we have https://github.com/MSRSSP/litebox/issues/24
    let platform = Box::leak(Box::new(Platform::new(
        None,
        litebox::platform::trivial_providers::ImpossiblePunchthroughProvider {},
        litebox_shim_linux::syscall_entry,
    )));
    let initial_file_system = {
        let in_mem = litebox::fs::in_mem::FileSystem::new(&*platform);
        let tar_data = if let Some(tar_file) = cli_args.initial_files.as_ref() {
            if tar_file.extension().and_then(|x| x.to_str()) != Some("tar") {
                anyhow::bail!("Expected a .tar file, found {}", tar_file.display());
            }
            std::fs::read(tar_file)
                .map_err(|e| anyhow!("Could not read tar file at {}: {}", tar_file.display(), e))?
        } else {
            litebox::fs::tar_ro::empty_tar_file()
        };
        let tar_ro = litebox::fs::tar_ro::FileSystem::new(&*platform, tar_data);
        litebox::fs::layered::FileSystem::new(&*platform, in_mem, tar_ro)
    };
    litebox_shim_linux::set_fs(initial_file_system);
    litebox_platform_multiplex::set_platform(platform);

    let loaded_program = litebox_shim_linux::loader::load_program(
        &cli_args.program_and_arguments[0],
        cli_args
            .program_and_arguments
            .iter()
            .map(|x| std::ffi::CString::new(x.bytes().collect::<Vec<u8>>()).unwrap())
            .collect(),
        // TODO: Initial environment variables
        vec![],
    )
    .unwrap();

    unsafe {
        trampoline::jump_to_entry_point(loaded_program.entry_point, loaded_program.user_stack_top)
    }
}

mod trampoline {
    core::arch::global_asm!(
        "
    .text
    .align  4
    .globl  jump_to_entry_point
    .type   jump_to_entry_point,@function
jump_to_entry_point:
    xor rdx, rdx
    mov     rsp, rsi
    jmp     rdi
    /* Should not reach. */
    hlt"
    );
    unsafe extern "C" {
        pub(crate) fn jump_to_entry_point(entry_point: usize, stack_pointer: usize) -> !;
    }
}
