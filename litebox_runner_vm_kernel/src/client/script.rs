// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Test client standing in for the normal world: runs the payload's
//! `cmds.json` against its `ta.elf`, or without it opens and closes a session
//! twice. `cmds.json` is the format of
//! `litebox_runner_optee_on_linux_userland/tests/*-cmds.json`. Every command
//! must succeed; TA outputs are logged, not checked.

use crate::payload::Payload;
use crate::service::Service;
use crate::service::optee::{Optee, Request};
use alloc::string::String;
use alloc::vec::Vec;
use litebox_common_optee::{TeeLogin, TeeResult, TeeUuid};
use litebox_shim_vm_kernel::optee::{
    Completion, EntryFunc, InParam, Invocation, NUM_PARAMS, OutParam,
};
use serde::Deserialize;

/// # Panics
///
/// On any failure, including a TA result other than success.
pub fn run(payload: &Payload, service: &mut Optee) {
    let ta = payload.file("ta.elf").expect("payload has no ta.elf");
    let head = litebox_common_optee::parse_ta_head(ta).expect("malformed TA header");
    let uuid = head.uuid;
    let commands: Vec<TaCommand> = match payload.file("cmds.json") {
        Some(json) => serde_json::from_slice(json).expect("malformed cmds.json"),
        None => alloc::vec![
            TaCommand::new(TaEntryFunc::OpenSession),
            TaCommand::new(TaEntryFunc::CloseSession),
            TaCommand::new(TaEntryFunc::OpenSession),
            TaCommand::new(TaEntryFunc::CloseSession),
        ],
    };
    let mut session = 0;
    for (index, cmd) in commands.iter().enumerate() {
        let func = cmd.func_id.into();
        let invocation = Invocation {
            func,
            session,
            cmd_id: cmd.cmd_id,
            login: cmd
                .client_identity
                .as_ref()
                .map_or(TeeLogin::User, |id| id.login.into()),
            client_uuid: cmd
                .client_identity
                .as_ref()
                .and_then(|id| id.uuid.as_deref())
                .map_or(TeeUuid::NIL, parse_uuid_or_panic),
            params: cmd.params(),
        };
        let completion = service.call(Request {
            ta: uuid,
            invocation,
        });
        assert!(
            completion.result == u32::from(TeeResult::Success),
            "command {index} ({func:?}): result {:#x} (origin {})",
            completion.result,
            completion.origin
        );
        if func == EntryFunc::OpenSession {
            session = completion.session;
            litebox_util_log::info!(session:% = session; "session opened");
        }
        log_outputs(&completion);
    }
}

fn log_outputs(completion: &Completion) {
    for (idx, param) in completion.params.iter().enumerate() {
        match param {
            OutParam::None => {}
            OutParam::Value { a, b } => litebox_util_log::info!(
                idx:% = idx,
                value_a:% = format_args!("{a:#x}"),
                value_b:% = format_args!("{b:#x}");
                "output"
            ),
            OutParam::Memref { data, size } => litebox_util_log::info!(
                idx:% = idx,
                size:% = size,
                data:? = &data[..data.len().min(16)];
                "output"
            ),
        }
    }
}

#[derive(Debug, Deserialize)]
struct TaCommand {
    func_id: TaEntryFunc,
    #[serde(default)]
    cmd_id: u32,
    #[serde(default)]
    args: Vec<TaCommandParam>,
    #[serde(default)]
    client_identity: Option<ClientIdentityJson>,
}

impl TaCommand {
    fn new(func_id: TaEntryFunc) -> Self {
        Self {
            func_id,
            cmd_id: 0,
            args: Vec::new(),
            client_identity: None,
        }
    }

    fn params(&self) -> [InParam; NUM_PARAMS] {
        assert!(self.args.len() <= NUM_PARAMS, "more than four arguments");
        let mut params: [InParam; NUM_PARAMS] = Default::default();
        for (param, arg) in params.iter_mut().zip(&self.args) {
            *param = arg.to_in_param();
        }
        params
    }
}

#[derive(Debug, Deserialize)]
struct ClientIdentityJson {
    #[serde(default)]
    login: ClientLoginJson,
    #[serde(default)]
    uuid: Option<String>,
}

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

fn parse_uuid_or_panic(s: &str) -> TeeUuid {
    let hex: String = s.chars().filter(|&c| c != '-').collect();
    assert!(
        hex.len() == 32 && hex.bytes().all(|b| b.is_ascii_hexdigit()),
        "client uuid must be 32 hex digits: {s:?}"
    );
    let mut bytes = [0u8; 16];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("checked hex digits");
    }
    TeeUuid::from_bytes(bytes)
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum TaEntryFunc {
    OpenSession,
    CloseSession,
    InvokeCommand,
}

impl From<TaEntryFunc> for EntryFunc {
    fn from(func: TaEntryFunc) -> Self {
        match func {
            TaEntryFunc::OpenSession => EntryFunc::OpenSession,
            TaEntryFunc::CloseSession => EntryFunc::CloseSession,
            TaEntryFunc::InvokeCommand => EntryFunc::InvokeCommand,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(tag = "param_type", rename_all = "snake_case")]
enum TaCommandParam {
    ValueInput {
        value_a: u64,
        value_b: u64,
    },
    ValueOutput,
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

impl TaCommandParam {
    fn to_in_param(&self) -> InParam {
        match self {
            Self::ValueInput { value_a, value_b } => InParam::ValueInput {
                a: *value_a,
                b: *value_b,
            },
            Self::ValueOutput => InParam::ValueOutput,
            Self::ValueInout { value_a, value_b } => InParam::ValueInout {
                a: *value_a,
                b: *value_b,
            },
            Self::MemrefInput { data_base64 } => InParam::MemrefInput(decode_base64(data_base64)),
            Self::MemrefOutput { buffer_size } => InParam::MemrefOutput {
                capacity: usize::try_from(*buffer_size).unwrap(),
            },
            Self::MemrefInout {
                data_base64,
                buffer_size,
            } => {
                let data = decode_base64(data_base64);
                let capacity = usize::try_from(*buffer_size).unwrap();
                assert!(
                    capacity >= data.len(),
                    "buffer size is smaller than the input data"
                );
                InParam::MemrefInout { data, capacity }
            }
        }
    }
}

fn decode_base64(data_base64: &str) -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(data_base64)
        .expect("Failed to decode base64 data")
}
