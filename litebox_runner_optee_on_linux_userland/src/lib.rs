use anyhow::Result;
use clap::Parser;
use litebox_common_optee::{TeeParamType, UteeEntryFunc, UteeParams};
use litebox_platform_multiplex::Platform;
use litebox_shim_optee::{
    allocate_param_buffer, register_session_id_elf_load_info, submit_optee_command,
};
use serde::Deserialize;
use std::path::PathBuf;

/// Test OP-TEE TAs with LiteBox on unmodified Linux
#[derive(Parser, Debug)]
pub struct CliArgs {
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

/// OP-TEE/TA message command. It consists of a function ID, command ID, and
/// up to four arguments.
#[derive(Debug, Deserialize)]
struct TaCommand {
    func_id: u32,
    cmd_id: u32,
    args: Vec<TaCommandArgument>,
}

/// An argument of OP-TEE/TA message command. It consists of a type and
/// two 64-bit values/references.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum TaCommandArgument {
    Value {
        param_type: u8,
        value_a: u64,
        value_b: u64,
    },
    MemrefInput {
        param_type: u8,
        data_base64: String,
    },
    MemrefInout {
        param_type: u8,
        data_base64: String,
        buffer_size: u64,
    },
    MemrefOutput {
        param_type: u8,
        buffer_size: u64,
    },
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
        let prog = PathBuf::from(&cli_args.program);
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

    let ta_commands: Vec<TaCommand> = {
        let json_path = PathBuf::from(&cli_args.command_sequence);
        let json_str = std::fs::read_to_string(json_path)?;
        serde_json::from_str(&json_str)?
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

    let params = UteeParams::new(); // dummy to secure an area in the stack
    let loaded_program =
        litebox_shim_optee::loader::load_elf_buffer(prog_data.as_slice(), &params).unwrap();

    // Currently, this runner only supports a single TA session.
    let session_id = 1;
    register_session_id_elf_load_info(session_id, &loaded_program);
    populate_optee_command_queue(session_id, &ta_commands);
    litebox_shim_optee::optee_command_loop();
}

fn populate_optee_command_queue(session_id: u32, ta_commands: &[TaCommand]) {
    let mut params = UteeParams::new();

    for ta_command in ta_commands {
        if ta_command.args.len() > UteeParams::TEE_NUM_PARAMS {
            panic!("Warning: ta_command has more than four arguments!");
        }
        for (i, arg) in ta_command.args.iter().enumerate() {
            match arg {
                TaCommandArgument::Value {
                    param_type,
                    value_a,
                    value_b,
                } => {
                    let param_type =
                        TeeParamType::try_from(*param_type).expect("Invalid param type");
                    if !matches!(
                        param_type,
                        TeeParamType::ValueInput
                            | TeeParamType::ValueOutput
                            | TeeParamType::ValueInout
                    ) {
                        panic!("Invalid param type");
                    }
                    params.set_type(i, param_type).unwrap();
                    params.set_values(i, *value_a, *value_b).unwrap();
                }
                TaCommandArgument::MemrefInput {
                    param_type,
                    data_base64,
                } => {
                    let param_type =
                        TeeParamType::try_from(*param_type).expect("Invalid param type");
                    if !matches!(param_type, TeeParamType::MemrefInput) {
                        panic!("Invalid param type");
                    }
                    params.set_type(i, param_type).unwrap();

                    let decode_buf_size = base64::decoded_len_estimate(data_base64.len());
                    let param_buf_addr =
                        allocate_param_buffer(usize::try_from(decode_buf_size).unwrap())
                            .expect("Failed to allocate memory for MemrefInput argument");
                    let length = base64::engine::Engine::decode_slice(
                        &base64::engine::general_purpose::STANDARD,
                        data_base64.as_bytes(),
                        unsafe {
                            &mut *core::ptr::slice_from_raw_parts_mut(
                                param_buf_addr as *mut u8,
                                decode_buf_size,
                            )
                        },
                    )
                    .expect("Failed to decode base64 data");

                    params
                        .set_values(
                            i,
                            u64::try_from(param_buf_addr).unwrap(),
                            u64::try_from(length).unwrap(),
                        )
                        .unwrap();
                }
                TaCommandArgument::MemrefInout {
                    param_type,
                    data_base64,
                    buffer_size,
                } => {
                    let param_type =
                        TeeParamType::try_from(*param_type).expect("Invalid param type");
                    if !matches!(param_type, TeeParamType::MemrefInout) {
                        panic!("Invalid param type");
                    }
                    params.set_type(i, param_type).unwrap();

                    let decode_buf_size = base64::decoded_len_estimate(data_base64.len());
                    let param_buf_addr = allocate_param_buffer(core::cmp::max(
                        usize::try_from(*buffer_size).unwrap(),
                        decode_buf_size,
                    ))
                    .expect("Failed to allocate memory for MemrefInout argument");
                    let length = base64::engine::Engine::decode_slice(
                        &base64::engine::general_purpose::STANDARD,
                        data_base64.as_bytes(),
                        unsafe {
                            &mut *core::ptr::slice_from_raw_parts_mut(
                                param_buf_addr as *mut u8,
                                decode_buf_size,
                            )
                        },
                    )
                    .expect("Failed to decode base64 data");
                    if *buffer_size < u64::try_from(length).unwrap() {
                        panic!("Buffer size is smaller than input data size");
                    }

                    params
                        .set_values(i, u64::try_from(param_buf_addr).unwrap(), *buffer_size)
                        .unwrap();
                }
                TaCommandArgument::MemrefOutput {
                    param_type,
                    buffer_size,
                } => {
                    let param_type =
                        TeeParamType::try_from(*param_type).expect("Invalid param type");
                    if !matches!(param_type, TeeParamType::MemrefOutput) {
                        panic!("Invalid param type");
                    }
                    params.set_type(i, param_type).unwrap();
                    let param_buf_addr = allocate_param_buffer(*buffer_size as usize)
                        .expect("Failed to allocate memory for MemrefOutput argument");
                    params
                        .set_values(i, u64::try_from(param_buf_addr).unwrap(), *buffer_size)
                        .unwrap();
                }
            }
        }
        for i in ta_command.args.len()..UteeParams::TEE_NUM_PARAMS {
            params.set_type(i, TeeParamType::None).unwrap();
        }

        submit_optee_command(
            session_id,
            UteeEntryFunc::try_from(ta_command.func_id).expect("Invalid function ID"),
            &params,
            ta_command.cmd_id,
        );
    }
}
