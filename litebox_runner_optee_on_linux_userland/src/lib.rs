use anyhow::Result;
use clap::Parser;
use litebox::platform::ThreadLocalStorageProvider;
use litebox_common_optee::UteeEntryFunc;
use litebox_platform_multiplex::Platform;
use litebox_shim_optee::{
    UteeParamsTyped, optee_command_dispatcher, register_session_id_elf_load_info,
    submit_optee_command,
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

    // This runner supports JSON-formatted OP-TEE TA command sequence for ease of development and testing.
    let ta_commands: Vec<TaCommandBase64> = {
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

    let loaded_program = litebox_shim_optee::loader::load_elf_buffer(prog_data.as_slice()).unwrap();

    // Currently, this runner supports a single TA session. Also, for simplicity,
    // it uses `tid` stored in LiteBox's TLS as a session ID.
    let tid = litebox_platform_multiplex::platform()
        .with_thread_local_storage_mut(|tls| tls.current_task.tid);
    #[allow(clippy::cast_sign_loss)]
    let session_id = tid as u32;

    assert!(
        register_session_id_elf_load_info(session_id, loaded_program),
        "session ID {session_id} already exists"
    );

    populate_optee_command_queue(session_id, &ta_commands);
    optee_command_dispatcher(session_id, false);
}

/// OP-TEE/TA message command (base64 encoded). It consists of a function ID,
/// command ID, and up to four arguments. This is base64 encoded to enable
/// JSON-formatted input files.
/// TODO: use JSON Schema if we need to validate JSON or we could use Protobuf instead
#[derive(Debug, Deserialize)]
struct TaCommandBase64 {
    func_id: TaEntryFunc,
    #[serde(default)]
    cmd_id: u32,
    #[serde(default)]
    args: Vec<TaCommandParamsBase64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaEntryFunc {
    OpenSession,
    CloseSession,
    InvokeCommand,
}

/// An argument of OP-TEE/TA message command (base64 encoded). It consists of
/// a type and two 64-bit values/references. This is base64 encoded to enable
/// JSON-formatted input files.
#[derive(Debug, Deserialize)]
#[serde(tag = "param_type", rename_all = "snake_case")]
enum TaCommandParamsBase64 {
    ValueInput {
        value_a: u64,
        value_b: u64,
    },
    ValueOutput {},
    ValueInout {
        value_a: u64,
        value_b: u64,
    },
    MemrefInput {
        data_base64: String,
    },
    MemrefOutput {
        buffer_size: u64,
    },
    MemrefInout {
        data_base64: String,
        buffer_size: u64,
    },
}

impl TaCommandParamsBase64 {
    pub fn as_utee_params_typed(&self) -> UteeParamsTyped {
        match self {
            TaCommandParamsBase64::ValueInput { value_a, value_b } => UteeParamsTyped::ValueInput {
                value_a: *value_a,
                value_b: *value_b,
            },
            TaCommandParamsBase64::ValueOutput {} => UteeParamsTyped::ValueOutput {},
            TaCommandParamsBase64::ValueInout { value_a, value_b } => UteeParamsTyped::ValueInout {
                value_a: *value_a,
                value_b: *value_b,
            },
            TaCommandParamsBase64::MemrefInput { data_base64 } => UteeParamsTyped::MemrefInput {
                data: Self::decode_base64(data_base64).into_boxed_slice(),
            },
            TaCommandParamsBase64::MemrefOutput { buffer_size } => UteeParamsTyped::MemrefOutput {
                buffer_size: usize::try_from(*buffer_size).unwrap(),
            },
            TaCommandParamsBase64::MemrefInout {
                data_base64,
                buffer_size,
            } => {
                let decoded_data = Self::decode_base64(data_base64);
                let buffer_size = usize::try_from(*buffer_size).unwrap();
                assert!(
                    buffer_size >= decoded_data.len(),
                    "Buffer size is smaller than input data size"
                );
                UteeParamsTyped::MemrefInout {
                    data: decoded_data.into_boxed_slice(),
                    buffer_size,
                }
            }
        }
    }

    fn decode_base64(data_base64: &str) -> Vec<u8> {
        let buf_size = base64::decoded_len_estimate(data_base64.len());
        let mut buffer = vec![0u8; buf_size];
        let length = base64::engine::Engine::decode_slice(
            &base64::engine::general_purpose::STANDARD,
            data_base64.as_bytes(),
            buffer.as_mut_slice(),
        )
        .expect("Failed to decode base64 data");
        buffer.truncate(length);
        buffer
    }
}

fn populate_optee_command_queue(session_id: u32, ta_commands: &[TaCommandBase64]) {
    for ta_command in ta_commands {
        assert!(
            (ta_command.args.len() <= UteeParamsTyped::TEE_NUM_PARAMS),
            "ta_command has more than four arguments."
        );

        let mut params = [const { UteeParamsTyped::None }; UteeParamsTyped::TEE_NUM_PARAMS];
        for (param, arg) in params.iter_mut().zip(&ta_command.args) {
            *param = arg.as_utee_params_typed();
        }

        let func_id = match ta_command.func_id {
            TaEntryFunc::OpenSession => UteeEntryFunc::OpenSession,
            TaEntryFunc::CloseSession => UteeEntryFunc::CloseSession,
            TaEntryFunc::InvokeCommand => UteeEntryFunc::InvokeCommand,
        };

        submit_optee_command(session_id, func_id, params, ta_command.cmd_id);
    }
}
