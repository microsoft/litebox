use anyhow::{Result, anyhow};
use clap::Parser;
use litebox::LiteBox;
use litebox::fs::FileSystem as _;
use litebox_platform_multiplex::Platform;
use std::os::linux::fs::MetadataExt as _;
use std::path::PathBuf;

/// Run Linux programs with LiteBox on unmodified Linux
#[derive(Parser, Debug)]
pub struct CliArgs {
    /// The program and arguments passed to it (e.g., `python3 --version`)
    #[arg(required = true, trailing_var_arg = true, value_hint = clap::ValueHint::CommandWithArguments)]
    pub program_and_arguments: Vec<String>,
    /// Environment variables passed to the program (`K=V` pairs; can be invoked multiple times)
    #[arg(long = "env")]
    pub environment_variables: Vec<String>,
    /// Forward the existing environment variables
    #[arg(long = "forward-env")]
    pub forward_environment_variables: bool,
    /// Allow using unstable options
    #[arg(short = 'Z', long = "unstable")]
    pub unstable: bool,
    /// Pre-fill files into the initial file system state
    // TODO: Might want to extend this to support full directories at some point?
    #[arg(long = "insert-file", value_hint = clap::ValueHint::FilePath,
          requires = "unstable", help_heading = "Unstable Options")]
    pub insert_files: Vec<PathBuf>,
    /// Pre-fill the files in this tar file into the initial file system state
    #[arg(long = "initial-files", value_name = "PATH_TO_TAR", value_hint = clap::ValueHint::FilePath,
          requires = "unstable", help_heading = "Unstable Options")]
    pub initial_files: Option<PathBuf>,
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
}

/// Run Linux programs with LiteBox on unmodified Linux
///
/// # Panics
///
/// Can panic if any particulars of the environment are not set up as expected. Ideally, would not
/// panic. If it does actually panic, then ping the authors of LiteBox, and likely a better error
/// message could be thrown instead.
#[expect(clippy::too_many_lines)]
pub fn run(cli_args: CliArgs) -> Result<()> {
    if !cli_args.insert_files.is_empty() {
        unimplemented!(
            "this should (hopefully soon) have a nicer interface to support loading in files"
        )
    }

    let (ancestor_modes, prog_data): (Vec<litebox::fs::Mode>, Vec<u8>) = {
        let prog = PathBuf::from(&cli_args.program_and_arguments[0]);
        let ancestors: Vec<_> = prog.ancestors().collect();
        let modes: Vec<_> = ancestors
            .into_iter()
            .rev()
            .skip(1)
            .map(|path| litebox::fs::Mode::from_bits(path.metadata().unwrap().st_mode()).unwrap())
            .collect();
        let data = std::fs::read(prog).unwrap();
        let data = if cli_args.rewrite_syscalls {
            litebox_syscall_rewriter::hook_syscalls_in_elf(&data, None).unwrap()
        } else {
            data
        };
        (modes, data)
    };
    let tar_data = if let Some(tar_file) = cli_args.initial_files.as_ref() {
        if tar_file.extension().and_then(|x| x.to_str()) != Some("tar") {
            anyhow::bail!("Expected a .tar file, found {}", tar_file.display());
        }
        std::fs::read(tar_file)
            .map_err(|e| anyhow!("Could not read tar file at {}: {}", tar_file.display(), e))?
    } else {
        litebox::fs::tar_ro::empty_tar_file()
    };

    // TODO(jb): Clean up platform initialization once we have https://github.com/MSRSSP/litebox/issues/24
    //
    // TODO: We also need to pick the type of syscall interception based on whether we want
    // systrap/sigsys interception, or binary rewriting interception. Currently
    // `litebox_platform_linux_userland` does not provide a way to pick between the two.
    let platform = Platform::new(
        None,
        litebox::platform::trivial_providers::ImpossiblePunchthroughProvider {},
    );
    let litebox = LiteBox::new(platform);
    let initial_file_system = {
        let mut in_mem = litebox::fs::in_mem::FileSystem::new(&litebox);
        in_mem.with_root_privileges(|fs| {
            let prog = PathBuf::from(&cli_args.program_and_arguments[0]);
            let ancestors: Vec<_> = prog.ancestors().collect();
            for (path, &mode) in ancestors
                .into_iter()
                .skip(1)
                .rev()
                .skip(1)
                .zip(&ancestor_modes)
            {
                fs.mkdir(path.to_str().unwrap(), mode).unwrap();
            }
            let fd = fs
                .open(
                    prog.to_str().unwrap(),
                    litebox::fs::OFlags::WRONLY | litebox::fs::OFlags::CREAT,
                    *ancestor_modes.last().unwrap(),
                )
                .unwrap();
            let mut data = prog_data.as_slice();
            while !data.is_empty() {
                let len = fs.write(&fd, data, None).unwrap();
                data = &data[len..];
            }
            fs.close(fd).unwrap();
        });
        let tar_ro = litebox::fs::tar_ro::FileSystem::new(&litebox, tar_data);
        let dev_stdio = litebox::fs::devices::stdio::FileSystem::new(&litebox);
        litebox::fs::layered::FileSystem::new(
            &litebox,
            in_mem,
            litebox::fs::layered::FileSystem::new(
                &litebox,
                dev_stdio,
                tar_ro,
                litebox::fs::layered::LayeringSemantics::LowerLayerReadOnly,
            ),
            litebox::fs::layered::LayeringSemantics::LowerLayerWritableFiles,
        )
    };
    litebox_shim_linux::set_fs(initial_file_system);
    litebox_platform_multiplex::set_platform(platform);
    platform.enable_syscall_interception_with(litebox_shim_linux::syscall_entry);

    let argv = cli_args
        .program_and_arguments
        .iter()
        .map(|x| std::ffi::CString::new(x.bytes().collect::<Vec<u8>>()).unwrap())
        .collect();
    let envp: Vec<_> = cli_args
        .environment_variables
        .iter()
        .map(|x| std::ffi::CString::new(x.bytes().collect::<Vec<u8>>()).unwrap())
        .collect();
    let envp = if cli_args.forward_environment_variables {
        envp.into_iter()
            .chain(std::env::vars().map(|(k, v)| {
                std::ffi::CString::new(
                    k.bytes()
                        .chain([b'='])
                        .chain(v.bytes())
                        .collect::<Vec<u8>>(),
                )
                .unwrap()
            }))
            .collect()
    } else {
        envp
    };

    let loaded_program =
        litebox_shim_linux::loader::load_program(&cli_args.program_and_arguments[0], argv, envp)
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
