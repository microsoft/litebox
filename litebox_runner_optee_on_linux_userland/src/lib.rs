use anyhow::Result;
use clap::Parser;
use litebox_common_optee::{TeeParamType, UteeEntryFunc, UteeParams};
use litebox_platform_multiplex::Platform;
use std::path::PathBuf;

/// Test OP-TEE TAs with LiteBox on unmodified Linux
#[derive(Parser, Debug)]
pub struct CliArgs {
    /// The TA and arguments passed to it
    #[arg(required = true, trailing_var_arg = true, value_hint = clap::ValueHint::CommandWithArguments)]
    pub program_and_arguments: Vec<String>,
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
        default_value = "seccomp"
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

/// Test OP-TEE TAs with LiteBox on unmodified Linux
///
/// # Panics
///
/// Can panic if any particulars of the environment are not set up as expected. Ideally, would not
/// panic. If it does actually panic, then ping the authors of LiteBox, and likely a better error
/// message could be thrown instead.
pub fn run(cli_args: CliArgs) -> Result<()> {
    let prog_data: Vec<u8> = {
        let prog = PathBuf::from(&cli_args.program_and_arguments[0]);
        let data = std::fs::read(prog).unwrap();
        #[allow(clippy::let_and_return)]
        let data = if cli_args.rewrite_syscalls {
            // capstone declares a global allocator in conflict with our own.
            // https://github.com/capstone-rust/capstone-rs/blob/14e855ca58400f454cb7ceb87d2c5e7b635ce498/capstone-rs/src/lib.rs#L16
            // litebox_syscall_rewriter::hook_syscalls_in_elf(&data, None).unwrap()
            // Might be a bug in `capstone-rs`: https://github.com/capstone-rust/capstone-rs/pull/171
            todo!()
        } else {
            data
        };
        data
    };

    // TODO(jb): Clean up platform initialization once we have https://github.com/MSRSSP/litebox/issues/24
    //
    // TODO: We also need to pick the type of syscall interception based on whether we want
    // systrap/sigsys interception, or binary rewriting interception. Currently
    // `litebox_platform_linux_userland` does not provide a way to pick between the two.
    let platform = Platform::new(None);
    litebox_platform_multiplex::set_platform(platform);
    platform.register_syscall_handler(litebox_shim_optee::handle_syscall_request);
    match cli_args.interception_backend {
        InterceptionBackend::Seccomp => platform.enable_seccomp_based_syscall_interception(),
        InterceptionBackend::Rewriter => {}
    }

    // TODO: obtain these parameters, function ID, and command ID from the command line arguments or
    // some other means (e.g., config file).
    let mut params = UteeParams::new();
    params.set_type(0, TeeParamType::None).unwrap();
    params.set_type(1, TeeParamType::None).unwrap();
    params.set_type(2, TeeParamType::None).unwrap();
    params.set_type(3, TeeParamType::None).unwrap();
    let params = params;

    let loaded_program =
        litebox_shim_optee::loader::load_elf_buffer(prog_data.as_slice(), &params).unwrap();

    // TODO: we need an event loop here, because TAs expect repetitive entrances with
    // different arguments (i.e., different function ID, different command ID, and different `UteeParams`).
    // session ID is determined by the kernel (this runner in this case).
    unsafe {
        jump_to_entry_point(
            usize::try_from(UteeEntryFunc::OpenSession as u32)
                .expect("UteeEntryFunc should fit in usize"),
            1,
            loaded_program.params_address,
            0,
            loaded_program.entry_point,
            loaded_program.user_stack_top,
        );
    }
}

/// TAs obtain four arguments through CPU registers:
/// - rdi: function ID
/// - rsi: session ID
/// - rdx: the address of parameters
/// - rcx: command ID
#[unsafe(naked)]
unsafe extern "C" fn jump_to_entry_point(
    func: usize,
    session_id: usize,
    params: usize,
    cmd_id: usize,
    entry_point: usize,
    user_stack_top: usize,
) -> ! {
    core::arch::naked_asm!("mov rsp, r9", "jmp r8", "hlt");
}
