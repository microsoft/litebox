use anyhow::Result;
use clap::Parser;
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

/// Run Linux programs with LiteBox on unmodified Linux
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

    let loaded_program = litebox_shim_optee::loader::load_elf_buffer(prog_data.as_slice()).unwrap();

    // TODO: we need an event loop here, because TAs expect repetitive entrances with different arguments.
    // TA is not a stand alone application.
    unsafe {
        trampoline::jump_to_entry_point(loaded_program.entry_point, loaded_program.user_stack_top)
    }
}

mod trampoline {
    #[cfg(target_arch = "x86_64")]
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
    #[cfg(target_arch = "x86")]
    core::arch::global_asm!(
        "
    .text
    .align  4
    .globl  jump_to_entry_point
    .type   jump_to_entry_point,@function
jump_to_entry_point:
    xor     edx, edx
    mov     ebx, [esp + 4]
    mov     eax, [esp + 8]
    mov     esp, eax
    jmp     ebx
    /* Should not reach. */
    hlt"
    );
    unsafe extern "C" {
        pub(crate) fn jump_to_entry_point(entry_point: usize, stack_pointer: usize) -> !;
    }
}
