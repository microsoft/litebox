// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! OP-TEE TA on Linux userland tests
//! OP-TEE TAs need clients to work with that this Linux userland runner lacks.
//! Instead, these tests use pre-defined JSON-formatted command sequences to test TAs.

use litebox::platform::RawConstPointer;
use litebox::utils::TruncateExt;
use litebox_common_optee::{
    TeeIdentity, TeeLogin, TeeParamType, TeeUuid, UteeEntryFunc, UteeParamOwned, UteeParams,
};
use litebox_shim_optee::session::session_manager;
use litebox_shim_optee::{LoadedProgram, UserConstPtr};
use serde::Deserialize;
use std::path::PathBuf;

/// Run the loaded TA with a sequence of test commands
pub fn run_ta_with_test_commands(
    shim: &litebox_shim_optee::OpteeShim,
    ldelf_bin: &[u8],
    ta_bin: &[u8],
    _prog_name: &str,
    json_path: &PathBuf,
) {
    let ta_commands: Vec<TaCommandBase64> = {
        let json_str = std::fs::read_to_string(json_path).unwrap();
        serde_json::from_str(&json_str).unwrap()
    };
    let mut ta_info: Option<LoadedProgram> = None;
    // The active session id for the TA. Set at OpenSession and reused for the
    // subsequent InvokeCommand entries on the same persistent session.
    let mut session_id: Option<u32> = None;

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
            continue;
        }
        if func_id == UteeEntryFunc::OpenSession {
            let ta_head = litebox_common_optee::parse_ta_head(ta_bin)
                .expect("Failed to parse TA header from ta_bin");
            let mut session_token = session_manager().try_acquire_open_session_token().unwrap();
            let open_session_id = session_token.session_id().unwrap();
            session_id = Some(open_session_id);
            // Emulate the client identity a real REE client would present.
            let client_identity = cmd.client_identity.as_ref().map_or(
                TeeIdentity {
                    login: TeeLogin::User,
                    uuid: TeeUuid::NIL,
                },
                ClientIdentityJson::to_tee_identity,
            );
            session_manager().set_session_client_identity(open_session_id, Some(client_identity));
            let loaded = shim
                .load_ldelf(ldelf_bin, ta_head.uuid, Some(ta_bin))
                .map_err(|_| {
                    panic!("Failed to load TA");
                })
                .unwrap();
            ta_info = Some(loaded);
            let info = ta_info.as_mut().unwrap();
            let mut ctx = litebox_common_linux::PtRegs::default();
            unsafe {
                litebox_platform_linux_userland::run_thread_ref(
                    info.entrypoints.as_ref().unwrap(),
                    &mut ctx,
                );
            }
            assert!(
                ctx.rax == 0,
                "ldelf exits with error: return_code={:#x}",
                ctx.rax
            );
            // The session persists across all commands, so disarm the token:
            // its drop must not recycle the id or clear the client identity.
            session_token.disarm();
        }

        if let Some(info) = ta_info.as_mut() {
            // In OP-TEE TA, each command invocation is like (re)starting the TA with a new stack with
            // loaded binary and heap. In that sense, we can create (and destroy) a stack
            // for each command freely.
            // `ta_info` is only `Some` after an OpenSession, which also sets
            // `session_id`, so this command runs on that established session.
            let session_id = session_id.expect("session id set by OpenSession");
            let _ = info
                .entrypoints
                .as_ref()
                .unwrap()
                .load_ta_context(
                    params.as_slice(),
                    session_id,
                    func_id as u32,
                    Some(cmd.cmd_id),
                )
                .map_err(|_| {
                    panic!("Failed to load TA context");
                });
            let mut ctx = litebox_common_linux::PtRegs::default();
            unsafe {
                litebox_platform_linux_userland::reenter_thread(
                    info.entrypoints.as_ref().unwrap(),
                    &mut ctx,
                );
            }
            assert!(
                ctx.rax == 0,
                "TA exits with error: return_code={:#x}",
                ctx.rax
            );
            // TA stores results in the `UteeParams` structure and/or buffers it refers to.
            if let Some(params_address) = info.params_address {
                let ptr = UserConstPtr::<UteeParams>::from_usize(params_address);
                let params = ptr.read_at_offset(0).expect("Failed to read UteeParams");
                handle_ta_command_output(&params);
            }
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
                    litebox_util_log::info!(
                        idx:% = idx,
                        value_a:% = format_args!("{:#x}", value_a),
                        value_b:% = format_args!("{:#x}", value_b);
                        "output"
                    );
                    // TODO: return the outcome to VTL0
                }
            }
            TeeParamType::MemrefOutput | TeeParamType::MemrefInout => {
                if let Ok(Some((addr, len))) = params.get_values(idx) {
                    let len: usize = len.trunc();
                    let ptr: UserConstPtr<u8> = UserConstPtr::from_ptr(addr as *const u8);
                    let slice = ptr.to_owned_slice(len).unwrap_or_default();
                    if slice.is_empty() {
                        litebox_util_log::info!(
                            idx:% = idx,
                            addr:% = format_args!("{:#x}", addr);
                            "output"
                        );
                    } else if slice.len() < 16 {
                        litebox_util_log::info!(
                            idx:% = idx,
                            addr:% = format_args!("{:#x}", addr),
                            data:? = slice;
                            "output"
                        );
                    } else {
                        litebox_util_log::info!(
                            idx:% = idx,
                            addr:% = format_args!("{:#x}", addr),
                            data:? = &slice[..16],
                            total:% = slice.len();
                            "output"
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
    #[serde(default)]
    client_identity: Option<ClientIdentityJson>,
}

/// Client identity for an `OpenSession`, parsed from the test JSON.
#[derive(Debug, Deserialize)]
struct ClientIdentityJson {
    #[serde(default)]
    login: ClientLoginJson,
    #[serde(default)]
    uuid: Option<String>,
}

/// JSON mirror of [`TeeLogin`].
#[derive(Debug, Default, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ClientLoginJson {
    Public,
    #[default]
    User,
    Group,
    Application,
    ApplicationUser,
    ApplicationGroup,
    ReeKernel,
    TrustedApp,
}

impl From<ClientLoginJson> for TeeLogin {
    fn from(login: ClientLoginJson) -> Self {
        match login {
            ClientLoginJson::Public => TeeLogin::Public,
            ClientLoginJson::User => TeeLogin::User,
            ClientLoginJson::Group => TeeLogin::Group,
            ClientLoginJson::Application => TeeLogin::Application,
            ClientLoginJson::ApplicationUser => TeeLogin::ApplicationUser,
            ClientLoginJson::ApplicationGroup => TeeLogin::ApplicationGroup,
            ClientLoginJson::ReeKernel => TeeLogin::ReeKernel,
            ClientLoginJson::TrustedApp => TeeLogin::TrustedApp,
        }
    }
}

impl ClientIdentityJson {
    fn to_tee_identity(&self) -> TeeIdentity {
        let uuid = self
            .uuid
            .as_deref()
            .map_or(TeeUuid::NIL, parse_uuid_or_panic);
        TeeIdentity {
            login: self.login.into(),
            uuid,
        }
    }
}

fn parse_uuid_or_panic(s: &str) -> TeeUuid {
    let hex: String = s.chars().filter(|&c| c != '-').collect();
    assert_eq!(hex.len(), 32, "client uuid must be 32 hex digits: {s:?}");
    let mut bytes = [0u8; 16];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .unwrap_or_else(|_| panic!("invalid hex in client uuid: {s:?}"));
    }
    TeeUuid::from_bytes(bytes)
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
            TaCommandParamsBase64::ValueOutput {} => UteeParamOwned::ValueOutput,
            TaCommandParamsBase64::ValueInout { value_a, value_b } => UteeParamOwned::ValueInout {
                value_a: *value_a,
                value_b: *value_b,
            },
            TaCommandParamsBase64::MemrefInput { data_base64 } => UteeParamOwned::MemrefInput {
                data: Self::decode_base64(data_base64).into_boxed_slice(),
            },
            TaCommandParamsBase64::MemrefOutput { buffer_size } => UteeParamOwned::MemrefOutput {
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
                UteeParamOwned::MemrefInout {
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
