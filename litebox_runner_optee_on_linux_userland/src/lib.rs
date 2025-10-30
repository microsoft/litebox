use anyhow::Result;
use clap::Parser;
use litebox_common_optee::{TeeIdentity, TeeLogin, TeeUuid, UteeEntryFunc, UteeParamOwned};
use litebox_platform_multiplex::Platform;
use litebox_shim_optee::loader::ElfLoadInfo;
use std::path::PathBuf;

#[cfg(test)]
use litebox_common_optee::{TeeParamType, UteeParams};
#[cfg(test)]
use serde::Deserialize;

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
    #[cfg(test)]
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

    let loaded_ta = litebox_shim_optee::loader::load_elf_buffer(prog_data.as_slice())?;

    #[cfg(not(test))]
    run_ta_with_default_commands(&loaded_ta);

    #[cfg(test)]
    let is_kmpp_ta = cli_args.program.contains("kmpp-ta.elf.hooked");
    #[cfg(test)]
    run_ta_with_test_commands(&loaded_ta, &ta_commands, is_kmpp_ta);
    Ok(())
}

#[cfg(not(test))]
fn run_ta_with_default_commands(ta_info: &ElfLoadInfo) {
    let mut session_id: u32 = 0;
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
            );
            session_id = litebox_shim_optee::get_session_id();
        }

        // In OP-TEE TA, each command invocation is like (re)starting the TA with a new stack with
        // loaded binary and heap. In that sense, we can create (and destroy) a stack
        // for each command freely.
        let stack =
            litebox_shim_optee::loader::init_stack(Some(ta_info.stack_base), params.as_slice())
                .expect("Failed to initialize stack with parameters");
        let mut pt_regs = litebox_shim_optee::loader::prepare_registers(
            ta_info,
            &stack,
            session_id,
            func_id as u32,
            None,
        );
        unsafe { litebox_platform_linux_userland::run_thread(&mut pt_regs) };

        if func_id == UteeEntryFunc::CloseSession {
            litebox_shim_optee::deinit_session();
        }
    }
}

/// Run the loaded TA with a sequence of test commands
#[cfg(test)]
fn run_ta_with_test_commands(
    ta_info: &ElfLoadInfo,
    ta_commands: &[TaCommandBase64],
    is_kmpp_ta: bool,
) {
    let mut session_id: u32 = 0;
    for cmd in ta_commands {
        assert!(
            (cmd.args.len() <= UteeParamOwned::TEE_NUM_PARAMS),
            "ta_command has more than four arguments."
        );

        let mut params = [const { UteeParamOwned::None }; UteeParamOwned::TEE_NUM_PARAMS];
        for (param, arg) in params.iter_mut().zip(&cmd.args) {
            *param = arg.as_utee_params_owned();
        }

        let func_id = match cmd.func_id {
            TaEntryFunc::OpenSession => UteeEntryFunc::OpenSession,
            TaEntryFunc::CloseSession => UteeEntryFunc::CloseSession,
            TaEntryFunc::InvokeCommand => UteeEntryFunc::InvokeCommand,
        };

        // special handling for the KMPP TA whose `OpenSession` expects a session ID that we cannot determine in advance
        if is_kmpp_ta
            && func_id == UteeEntryFunc::OpenSession
            && let UteeParamOwned::ValueInput {
                ref mut value_a,
                value_b: _,
            } = params[0]
        {
            *value_a = u64::from(session_id);
        }

        if func_id == UteeEntryFunc::OpenSession {
            let _litebox = litebox_shim_optee::init_session(
                &TeeUuid::default(),
                &TeeIdentity {
                    login: TeeLogin::User,
                    uuid: TeeUuid::default(),
                },
            );
            session_id = litebox_shim_optee::get_session_id();
        }

        let stack =
            litebox_shim_optee::loader::init_stack(Some(ta_info.stack_base), params.as_slice())
                .expect("Failed to initialize stack with parameters");
        let mut pt_regs = litebox_shim_optee::loader::prepare_registers(
            ta_info,
            &stack,
            session_id,
            func_id as u32,
            Some(cmd.cmd_id),
        );
        unsafe { litebox_platform_linux_userland::run_thread(&mut pt_regs) };
        // TA stores results in the `UteeParams` structure and/or buffers it refers to.
        let params = unsafe { &*(ta_info.params_address as *const UteeParams) };
        handle_ta_command_output(params);

        if func_id == UteeEntryFunc::CloseSession {
            litebox_shim_optee::deinit_session();
        }
    }
}

/// A function to retrieve the results of the OP-TEE TA command execution.
#[cfg(test)]
fn handle_ta_command_output(params: &UteeParams) {
    for idx in 0..UteeParams::TEE_NUM_PARAMS {
        let param_type = params.get_type(idx).expect("Failed to get parameter type");
        match param_type {
            TeeParamType::ValueOutput | TeeParamType::ValueInout => {
                if let Ok(Some((value_a, value_b))) = params.get_values(idx) {
                    #[cfg(debug_assertions)]
                    litebox::log_println!(
                        litebox_platform_multiplex::platform(),
                        "output (index: {}): {:#x} {:#x}",
                        idx,
                        value_a,
                        value_b,
                    );
                    // TODO: return the outcome to VTL0
                }
            }
            TeeParamType::MemrefOutput | TeeParamType::MemrefInout => {
                if let Ok(Some((addr, len))) = params.get_values(idx) {
                    let slice = unsafe {
                        &*core::ptr::slice_from_raw_parts(
                            addr as *const u8,
                            usize::try_from(len).unwrap_or(0),
                        )
                    };
                    #[cfg(debug_assertions)]
                    if slice.is_empty() {
                        litebox::log_println!(
                            litebox_platform_multiplex::platform(),
                            "output (index: {}): {:#x}",
                            idx,
                            addr
                        );
                    } else if slice.len() < 16 {
                        litebox::log_println!(
                            litebox_platform_multiplex::platform(),
                            "output (index: {}): {:#x} {:?}",
                            idx,
                            addr,
                            slice
                        );
                    } else {
                        litebox::log_println!(
                            litebox_platform_multiplex::platform(),
                            "output (index: {}): {:#x} {:?}... (total {} bytes)",
                            idx,
                            addr,
                            &slice[..16],
                            slice.len()
                        );
                    }
                    // TODO: return the outcome to VTL0
                }
            }
            _ => {}
        }
    }
}

/// OP-TEE/TA message command (base64 encoded). It consists of a function ID,
/// command ID, and up to four arguments. This is base64 encoded to enable
/// JSON-formatted input files.
/// TODO: use JSON Schema if we need to validate JSON or we could use Protobuf instead
#[cfg(test)]
#[derive(Debug, Deserialize)]
struct TaCommandBase64 {
    func_id: TaEntryFunc,
    #[serde(default)]
    cmd_id: u32,
    #[serde(default)]
    args: Vec<TaCommandParamsBase64>,
}

#[cfg(test)]
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
#[cfg(test)]
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

#[cfg(test)]
impl TaCommandParamsBase64 {
    pub fn as_utee_params_owned(&self) -> UteeParamOwned {
        match self {
            TaCommandParamsBase64::ValueInput { value_a, value_b } => UteeParamOwned::ValueInput {
                value_a: *value_a,
                value_b: *value_b,
            },
            TaCommandParamsBase64::ValueOutput {} => {
                UteeParamOwned::ValueOutput { out_address: None }
            }
            TaCommandParamsBase64::ValueInout { value_a, value_b } => UteeParamOwned::ValueInout {
                value_a: *value_a,
                value_b: *value_b,
                out_address: None,
            },
            TaCommandParamsBase64::MemrefInput { data_base64 } => UteeParamOwned::MemrefInput {
                data: Self::decode_base64(data_base64).into_boxed_slice(),
            },
            TaCommandParamsBase64::MemrefOutput { buffer_size } => UteeParamOwned::MemrefOutput {
                buffer_size: usize::try_from(*buffer_size).unwrap(),
                out_addresses: None,
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
                    out_addresses: None,
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
