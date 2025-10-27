use anyhow::Result;
use clap::Parser;
use hashbrown::HashMap;
use litebox::utils::ReinterpretUnsignedExt;
use litebox_common_optee::{OpteeTaCommand, UteeEntryFunc, UteeParamOwned};
use litebox_platform_multiplex::Platform;
use once_cell::race::OnceBox;
use serde::Deserialize;
use std::boxed::Box;
use std::collections::vec_deque::VecDeque;
use std::path::PathBuf;

mod command_dispatcher;
use command_dispatcher::{
    handle_optee_command_output, optee_ta_command_handler, register_session_id_elf_load_info,
    session_id_elf_load_info_map,
};

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
    platform.register_shim(&litebox_shim_optee::OpteeShim);
    match cli_args.interception_backend {
        InterceptionBackend::Seccomp => platform.enable_seccomp_based_syscall_interception(),
        InterceptionBackend::Rewriter => {}
    }

    let loaded_program = litebox_shim_optee::loader::load_elf_buffer(prog_data.as_slice()).unwrap();

    // Currently, this runner supports a single TA session. Also, for simplicity,
    // it uses `tid` as a session ID.
    let session_id = platform.init_task().tid.reinterpret_as_unsigned();
    litebox_shim_optee::set_session_id(session_id);

    assert!(
        register_session_id_elf_load_info(session_id, loaded_program),
        "redundant session ID is not allowed"
    );

    wait_for_client_command(session_id, &ta_commands);
    Ok(())
}

/// Runner for OP-TEE and LVBS is expected to wait for a client's commands and
/// deliver them to the corresponding handlers (it does nothing without clients).
/// Since this runner does not support a client (yet), it replays a given TA command log
/// to simulate a client (mainly for testing).
fn wait_for_client_command(session_id: u32, ta_commands: &[TaCommandBase64]) {
    populate_ta_command_replay_queue(session_id, ta_commands);
    replay_ta_commands(session_id);
}

/// Replay OP-TEE TA command logs to simulate a client. It dequeues commands from
/// the command queue and handles each of them by interacting with loaded TAs.
/// For now, it terminates the current thread if there is no commands left in the queue.
/// Instead, it can be an infinite loop with sleep to continously handle commands
/// (i.e., `UteeEntryFunc::InvokeCommand`) until it gets `UteeEntryFunc::CloseSession`
/// from the queue.
/// # Panics
/// This function panics if it cannot allocate a stack
pub fn replay_ta_commands(session_id: u32) {
    if let Some(cmd) = optee_command_replay_queue().pop(session_id) {
        optee_ta_command_handler(&cmd);
        handle_optee_command_output(session_id);
    } else {
        // no command left. terminate the thread for now
        session_id_elf_load_info_map().remove(session_id);
        optee_command_replay_queue().remove(session_id);
    }
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
    pub fn as_utee_params_typed(&self) -> UteeParamOwned {
        match self {
            TaCommandParamsBase64::ValueInput { value_a, value_b } => UteeParamOwned::ValueInput {
                value_a: *value_a,
                value_b: *value_b,
            },
            TaCommandParamsBase64::ValueOutput {} => UteeParamOwned::ValueOutput { out_address: 0 },
            TaCommandParamsBase64::ValueInout { value_a, value_b } => UteeParamOwned::ValueInout {
                value_a: *value_a,
                value_b: *value_b,
                out_address: 0,
            },
            TaCommandParamsBase64::MemrefInput { data_base64 } => UteeParamOwned::MemrefInput {
                data: Self::decode_base64(data_base64).into_boxed_slice(),
            },
            TaCommandParamsBase64::MemrefOutput { buffer_size } => UteeParamOwned::MemrefOutput {
                buffer_size: usize::try_from(*buffer_size).unwrap(),
                out_addresses: vec![].into(),
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
                UteeParamOwned::MemrefInout {
                    data: decoded_data.into_boxed_slice(),
                    buffer_size,
                    out_addresses: vec![].into(),
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

fn populate_ta_command_replay_queue(session_id: u32, ta_commands: &[TaCommandBase64]) {
    for ta_command in ta_commands {
        assert!(
            (ta_command.args.len() <= UteeParamOwned::TEE_NUM_PARAMS),
            "ta_command has more than four arguments."
        );

        let mut params = [const { UteeParamOwned::None }; UteeParamOwned::TEE_NUM_PARAMS];
        for (param, arg) in params.iter_mut().zip(&ta_command.args) {
            *param = arg.as_utee_params_typed();
        }

        let func_id = match ta_command.func_id {
            TaEntryFunc::OpenSession => UteeEntryFunc::OpenSession,
            TaEntryFunc::CloseSession => UteeEntryFunc::CloseSession,
            TaEntryFunc::InvokeCommand => UteeEntryFunc::InvokeCommand,
        };

        // special handling for the KMPP TA whose `OpenSession` expects the session ID
        if func_id == UteeEntryFunc::OpenSession
            && let UteeParamOwned::ValueInput {
                ref mut value_a,
                value_b: _,
            } = params[0]
            && *value_a == 0
        {
            *value_a = u64::from(session_id);
        }

        submit_ta_command(session_id, func_id, &params, ta_command.cmd_id);
    }
}

/// OP-TEE command replay queue
pub(crate) struct TaCommandQueue {
    inner: spin::mutex::SpinMutex<HashMap<u32, VecDeque<OpteeTaCommand>>>,
}

impl TaCommandQueue {
    pub fn new() -> Self {
        TaCommandQueue {
            inner: spin::mutex::SpinMutex::new(HashMap::new()),
        }
    }

    pub fn push(&self, cmd: OpteeTaCommand) {
        let session_id = match &cmd {
            OpteeTaCommand::OpenSession { session_id, .. }
            | OpteeTaCommand::CloseSession { session_id }
            | OpteeTaCommand::InvokeCommand { session_id, .. } => *session_id,
        };
        self.inner
            .lock()
            .entry(session_id)
            .or_default()
            .push_back(cmd);
    }

    pub fn pop(&self, session_id: u32) -> Option<OpteeTaCommand> {
        self.inner
            .lock()
            .get_mut(&session_id)
            .and_then(VecDeque::pop_front)
    }

    pub fn remove(&self, session_id: u32) {
        self.inner.lock().remove(&session_id);
    }
}

pub(crate) fn optee_command_replay_queue() -> &'static TaCommandQueue {
    static QUEUE: OnceBox<TaCommandQueue> = OnceBox::new();
    QUEUE.get_or_init(|| Box::new(TaCommandQueue::new()))
}

/// Push or enqueue an OP-TEE TA command to the command replay queue which will be
/// consumed by `command_dispatcher`.
pub fn submit_ta_command(
    session_id: u32,
    func: UteeEntryFunc,
    params: &[UteeParamOwned; UteeParamOwned::TEE_NUM_PARAMS],
    cmd_id: u32,
) {
    let cmd = match func {
        UteeEntryFunc::OpenSession => OpteeTaCommand::OpenSession {
            session_id,
            params: Box::new(params.clone()),
        },
        UteeEntryFunc::CloseSession => OpteeTaCommand::CloseSession { session_id },
        UteeEntryFunc::InvokeCommand => OpteeTaCommand::InvokeCommand {
            session_id,
            params: Box::new(params.clone()),
            cmd_id,
        },
        UteeEntryFunc::Unknown => return,
    };
    optee_command_replay_queue().push(cmd);
}
