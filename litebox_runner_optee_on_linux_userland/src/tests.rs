//! OP-TEE TA on Linux userland tests
//! OP-TEE TAs need clients to work with that this Linux userland runner lacks.
//! Instead, these tests use pre-defined JSON-formatted command sequences to test TAs.

use litebox_common_optee::{
    LdelfArg, TeeIdentity, TeeLogin, TeeParamType, TeeUuid, UteeEntryFunc, UteeParamOwned,
    UteeParams,
};
use litebox_shim_optee::loader::ElfLoadInfo;
use serde::Deserialize;
use std::path::PathBuf;

/// Run the loaded TA with a sequence of test commands
pub fn run_ta_with_test_commands(
    ldelf_bin: &[u8],
    ta_bin: &[u8],
    prog_name: &str,
    json_path: &PathBuf,
) {
    let ta_commands: Vec<TaCommandBase64> = {
        let json_str = std::fs::read_to_string(json_path).unwrap();
        serde_json::from_str(&json_str).unwrap()
    };
    let is_kmpp_ta = prog_name.contains("kmpp-ta.elf.hooked");
    let mut ta_info: Option<ElfLoadInfo> = None;

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
        if func_id == UteeEntryFunc::CloseSession {
            litebox_shim_optee::deinit_session();
            continue;
        }

        if func_id == UteeEntryFunc::OpenSession {
            let _litebox = litebox_shim_optee::init_session(
                &TeeUuid::default(),
                &TeeIdentity {
                    login: TeeLogin::User,
                    uuid: TeeUuid::default(),
                },
                Some(ta_bin), // TODO: replace it with UUID-based TA loading
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
            assert!(
                pt_regs.rax == 0,
                "TA exits with error: return_code={:#x}",
                pt_regs.rax
            );

            let ldelf_arg_out = unsafe { &*(ldelf_arg_address as *const LdelfArg) };
            let entry_func = usize::try_from(ldelf_arg_out.entry_func).unwrap();
            litebox::log_println!(
                litebox_platform_multiplex::platform(),
                "ldelf has loaded TA: entry_func = {:#x}",
                entry_func,
            );

            litebox_shim_optee::set_ta_loaded();
            let base = litebox_shim_optee::get_ta_base_addr()
                .ok_or(litebox_common_linux::errno::Errno::ENOENT)
                .expect("TA base addr not set");
            litebox_shim_optee::loader::load_ta_trampoline(ta_bin, base)
                .expect("Failed to load trampoline");
            litebox_shim_optee::loader::allocate_guest_tls(None).expect("Failed to allocate TLS");

            ta_info = Some(ElfLoadInfo {
                entry_point: entry_func,
                stack_base: ldelf_info.stack_base,
                params_address: ldelf_info.params_address,
                ldelf_arg_address: None,
            });

            // special handling for the KMPP TA whose `OpenSession` expects a session ID that we cannot determine in advance
            if is_kmpp_ta
                && let UteeParamOwned::ValueInput {
                    ref mut value_a,
                    value_b: _,
                } = params[0]
            {
                *value_a = u64::from(litebox_shim_optee::get_session_id());
            }
        }

        if let Some(ta_info) = ta_info {
            let stack =
                litebox_shim_optee::loader::init_stack(Some(ta_info.stack_base), params.as_slice())
                    .expect("Failed to initialize stack with parameters");
            let mut pt_regs = litebox_shim_optee::loader::prepare_registers(
                &ta_info,
                &stack,
                litebox_shim_optee::get_session_id(),
                func_id as u32,
                Some(cmd.cmd_id),
            );
            unsafe {
                litebox_platform_linux_userland::run_thread(
                    litebox_shim_optee::OpteeShim,
                    &mut pt_regs,
                );
            };
            assert!(
                pt_regs.rax == 0,
                "TA exits with error: return_code={:#x}",
                pt_regs.rax
            );
            // TA stores results in the `UteeParams` structure and/or buffers it refers to.
            let params = unsafe { &*(ta_info.params_address as *const UteeParams) };
            handle_ta_command_output(params);
        } else {
            panic!("TA info is not available.");
        }
    }
}

/// A function to retrieve the results of the OP-TEE TA command execution.
fn handle_ta_command_output(params: &UteeParams) {
    for idx in 0..UteeParams::TEE_NUM_PARAMS {
        let param_type = params.get_type(idx).expect("Failed to get parameter type");
        match param_type {
            TeeParamType::ValueOutput | TeeParamType::ValueInout => {
                if let Ok(Some((value_a, value_b))) = params.get_values(idx) {
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
#[derive(Debug, Deserialize)]
pub struct TaCommandBase64 {
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
