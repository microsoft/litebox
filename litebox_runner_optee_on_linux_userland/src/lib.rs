use anyhow::Result;
use clap::Parser;
use litebox_common_optee::{
    LdelfArg, TeeIdentity, TeeLogin, TeeUuid, UteeEntryFunc, UteeParamOwned,
};
use litebox_platform_multiplex::Platform;
use litebox_shim_optee::loader::ElfLoadInfo;
use std::path::PathBuf;

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

/// Test OP-TEE TAs with LiteBox on unmodified Linux
///
/// # Panics
///
/// Can panic if any particulars of the environment are not set up as expected. Ideally, would not
/// panic. If it does actually panic, then ping the authors of LiteBox, and likely a better error
/// message could be thrown instead.
pub fn run(cli_args: CliArgs) -> Result<()> {
    let ldelf_data: Vec<u8> = {
        let ldelf = PathBuf::from(&cli_args.ldelf);
        let data = std::fs::read(ldelf).unwrap();
        if cli_args.rewrite_syscalls {
            litebox_syscall_rewriter::hook_syscalls_in_elf(&data, None).unwrap()
        } else {
            data
        }
    };

    let prog_data: Vec<u8> = {
        let prog = PathBuf::from(&cli_args.program);
        let data = std::fs::read(prog).unwrap();
        if cli_args.rewrite_syscalls {
            litebox_syscall_rewriter::hook_syscalls_in_elf(&data, None).unwrap()
        } else {
            data
        }
    };

    // TODO(jb): Clean up platform initialization once we have https://github.com/MSRSSP/litebox/issues/24
    //
    // TODO: We also need to pick the type of syscall interception based on whether we want
    // systrap/sigsys interception, or binary rewriting interception. Currently
    // `litebox_platform_linux_userland` does not provide a way to pick between the two.
    let platform = Platform::new(None);
    litebox_platform_multiplex::set_platform(platform);
    match cli_args.interception_backend {
        InterceptionBackend::Seccomp => platform.enable_seccomp_based_syscall_interception(),
        InterceptionBackend::Rewriter => {}
    }

    if cli_args.command_sequence.is_empty() {
        run_ta_with_default_commands(ldelf_data.as_slice(), prog_data.as_slice());
    } else {
        tests::run_ta_with_test_commands(
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
fn run_ta_with_default_commands(ldelf_bin: &[u8], ta_bin: &[u8]) {
    for func_id in [UteeEntryFunc::OpenSession, UteeEntryFunc::CloseSession] {
        let params = [const { UteeParamOwned::None }; UteeParamOwned::TEE_NUM_PARAMS];

        if func_id == UteeEntryFunc::OpenSession {
            // Each OP-TEE TA has its own UUID.
            // The client of a session can be a normal-world (VTL0) application or another TA (at VTL1).
            // The VTL0 kernel is expected to provide the client identity information.
            let _litebox = litebox_shim_optee::init_session(
                &TeeUuid::default(),
                &TeeIdentity {
                    login: TeeLogin::User,
                    uuid: TeeUuid::default(),
                },
                Some(ta_bin), // TODO: replace this with UUID-based TA loading
            );

            let ldelf_info = litebox_shim_optee::loader::load_elf_buffer(ldelf_bin)
                .expect("Failed to load ldelf");
            let Some(ldelf_arg_address) = ldelf_info.ldelf_arg_address else {
                panic!("ldelf_arg_address not found");
            };
            let ldelf_arg = LdelfArg::new(); // TODO: set TA UUID

            let stack = litebox_shim_optee::loader::init_ldelf_stack(
                Some(ldelf_info.stack_base),
                &ldelf_arg,
            )
            .expect("Failed to initialize stack for ldelf");
            let mut pt_regs =
                litebox_shim_optee::loader::prepare_ldelf_registers(&ldelf_info, &stack);
            unsafe {
                litebox_platform_linux_userland::run_thread(
                    litebox_shim_optee::OpteeShim,
                    &mut pt_regs,
                );
            };

            // Note: `ldelf` allocates stack (returned via `stack_ptr`) but we don't use it here.
            // Need to revisit this to see whether the stack is large enough for our use cases (e.g.,
            // copy owned data through stack to minimize TOCTTOU threats).
            let ldelf_arg_out = unsafe { &*(ldelf_arg_address as *const LdelfArg) };
            let entry_func = usize::try_from(ldelf_arg_out.entry_func).unwrap();
            #[cfg(debug_assertions)]
            litebox::log_println!(
                litebox_platform_multiplex::platform(),
                "ldelf has loaded TA: entry_func is at {:#x}",
                entry_func,
            );

            litebox_shim_optee::set_ta_loaded();

            let base = litebox_shim_optee::get_ta_base_addr()
                .ok_or(litebox_common_linux::errno::Errno::ENOENT)
                .expect("TA base addr not set");
            litebox_shim_optee::loader::load_ta_trampoline(ta_bin, base)
                .expect("Failed to load trampoline");
            litebox_shim_optee::loader::allocate_guest_tls(None).expect("Failed to allocate TLS");

            let ta_info = ElfLoadInfo {
                entry_point: entry_func,
                stack_base: ldelf_info.stack_base,
                params_address: ldelf_info.params_address,
                ldelf_arg_address: None,
            };

            // In OP-TEE TA, each command invocation is like (re)starting the TA with a new stack with
            // loaded binary and heap. In that sense, we can create (and destroy) a stack
            // for each command freely.
            let stack =
                litebox_shim_optee::loader::init_stack(Some(ta_info.stack_base), params.as_slice())
                    .expect("Failed to initialize stack with parameters");
            let mut pt_regs = litebox_shim_optee::loader::prepare_registers(
                &ta_info,
                &stack,
                litebox_shim_optee::get_session_id(),
                func_id as u32,
                None,
            );
            unsafe {
                litebox_platform_linux_userland::run_thread(
                    litebox_shim_optee::OpteeShim,
                    &mut pt_regs,
                );
            };
        } else if func_id == UteeEntryFunc::CloseSession {
            litebox_shim_optee::deinit_session();
        }
    }
}
