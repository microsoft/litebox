// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Test client standing in for the normal world: runs the payload's
//! `cmds.json` against its `tas/<name>.elf`, or without it opens and closes a
//! session to the only TA twice.
//!
//! `cmds.json` is the format of
//! `litebox_runner_optee_on_linux_userland/tests/*-cmds.json` plus optional:
//! - `ta`: the `open_session` target; required with more than one TA.
//! - `session`: a label (default `default`).
//! - `expect_result`: default success.
//! - `expect_instances`: live instances after the command.
//! - In output arguments: `expect_value_a`, `expect_value_b`, `expect_size`,
//!   `expect_data_base64`.

use crate::payload::Payload;
use crate::service::Service;
use crate::service::optee::{Optee, Request};
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use litebox_common_optee::{TeeLogin, TeeResult, TeeUuid};
use litebox_shim_vm_kernel::optee::{
    Completion, EntryFunc, InParam, Invocation, NUM_PARAMS, OutParam,
};
use serde::Deserialize;

const DEFAULT_SESSION: &str = "default";

/// # Panics
///
/// On any failure, including an unexpected TA result.
pub fn run(payload: &Payload, service: &mut Optee) {
    // A client knows its TAs' UUIDs.
    let tas: Vec<(&'static str, TeeUuid)> = payload
        .files_under("tas/")
        .filter_map(|(name, image)| {
            let name = name.strip_suffix(".elf")?;
            let head = litebox_common_optee::parse_ta_head(image)
                .unwrap_or_else(|| panic!("malformed TA header: {name}"));
            Some((name, head.uuid))
        })
        .collect();
    let commands: Vec<TaCommand> = match payload.file("cmds.json") {
        Some(json) => serde_json::from_slice(json).expect("malformed cmds.json"),
        None => alloc::vec![
            TaCommand::new(TaEntryFunc::OpenSession),
            TaCommand::new(TaEntryFunc::CloseSession),
            TaCommand::new(TaEntryFunc::OpenSession),
            TaCommand::new(TaEntryFunc::CloseSession),
        ],
    };
    let mut sessions: BTreeMap<String, u32> = BTreeMap::new();
    for (index, cmd) in commands.iter().enumerate() {
        let func = cmd.func_id.into();
        let label = cmd.session.as_deref().unwrap_or(DEFAULT_SESSION);
        let ta = if func == EntryFunc::OpenSession {
            target_ta(&tas, cmd.ta.as_deref())
        } else {
            TeeUuid::NIL
        };
        let invocation = Invocation {
            func,
            session: if func == EntryFunc::OpenSession {
                0
            } else {
                // An unknown label means an unknown session; 0 is never one.
                sessions.get(label).copied().unwrap_or(0)
            },
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
        let completion = service.call(Request { ta, invocation });
        let expected = cmd.expect_result.unwrap_or(TeeResult::Success.into());
        assert!(
            completion.result == expected,
            "command {index} ({func:?}, session {label:?}): \
             result {:#x} (origin {}), expected {expected:#x}",
            completion.result,
            completion.origin
        );
        // A closed session keeps its label, so later commands send its stale ID.
        if func == EntryFunc::OpenSession && completion.result == 0 {
            sessions.insert(label.into(), completion.session);
            litebox_util_log::info!(
                session:% = completion.session,
                label:% = label;
                "session opened"
            );
        }
        if let Some(expected) = cmd.expect_instances {
            assert_eq!(
                service.instance_count(),
                expected,
                "command {index}: live TA instances"
            );
        }
        log_outputs(&completion);
        for (arg, (param, out)) in cmd.args.iter().zip(&completion.params).enumerate() {
            param.check(out, |what| {
                panic!("command {index} ({func:?}, session {label:?}), argument {arg}: {what}")
            });
        }
    }
}

fn target_ta(tas: &[(&'static str, TeeUuid)], name: Option<&str>) -> TeeUuid {
    if let Some(name) = name {
        tas.iter()
            .find(|(ta, _)| *ta == name)
            .unwrap_or_else(|| panic!("no TA named {name:?}"))
            .1
    } else {
        assert!(tas.len() == 1, "`ta` is required with several TAs");
        tas[0].1
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
            OutParam::Memref { data, size } => {
                litebox_util_log::info!(
                    idx:% = idx,
                    size:% = size,
                    data:? = &data[..data.len().min(16)];
                    "output"
                );
                litebox_util_log::debug!(
                    idx:% = idx,
                    data_base64:% = encode_base64(data);
                    "output"
                );
            }
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
    #[serde(default)]
    ta: Option<String>,
    #[serde(default)]
    session: Option<String>,
    #[serde(default)]
    expect_result: Option<u32>,
    #[serde(default)]
    expect_instances: Option<usize>,
}

impl TaCommand {
    fn new(func_id: TaEntryFunc) -> Self {
        Self {
            func_id,
            cmd_id: 0,
            args: Vec::new(),
            client_identity: None,
            ta: None,
            session: None,
            expect_result: None,
            expect_instances: None,
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
    ValueOutput {
        #[serde(flatten)]
        expect: ExpectValue,
    },
    ValueInout {
        value_a: u64,
        value_b: u64,
        #[serde(flatten)]
        expect: ExpectValue,
    },
    MemrefInput {
        data_base64: String,
    },
    MemrefOutput {
        buffer_size: u64,
        #[serde(flatten)]
        expect: ExpectMemref,
    },
    MemrefInout {
        data_base64: String,
        buffer_size: u64,
        #[serde(flatten)]
        expect: ExpectMemref,
    },
}

#[derive(Debug, Default, Deserialize)]
struct ExpectValue {
    expect_value_a: Option<u64>,
    expect_value_b: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
struct ExpectMemref {
    expect_size: Option<u64>,
    expect_data_base64: Option<String>,
}

impl TaCommandParam {
    fn to_in_param(&self) -> InParam {
        match self {
            Self::ValueInput { value_a, value_b } => InParam::ValueInput {
                a: *value_a,
                b: *value_b,
            },
            Self::ValueOutput { .. } => InParam::ValueOutput,
            Self::ValueInout {
                value_a, value_b, ..
            } => InParam::ValueInout {
                a: *value_a,
                b: *value_b,
            },
            Self::MemrefInput { data_base64 } => InParam::MemrefInput(decode_base64(data_base64)),
            Self::MemrefOutput { buffer_size, .. } => InParam::MemrefOutput {
                capacity: usize::try_from(*buffer_size).unwrap(),
            },
            Self::MemrefInout {
                data_base64,
                buffer_size,
                ..
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

    /// Calls `fail` on an output that does not match the expectations.
    fn check(&self, out: &OutParam, fail: impl Fn(String)) {
        match (self, out) {
            (
                Self::ValueOutput { expect } | Self::ValueInout { expect, .. },
                OutParam::Value { a, b },
            ) => {
                for (name, expected, actual) in [
                    ("value_a", expect.expect_value_a, a),
                    ("value_b", expect.expect_value_b, b),
                ] {
                    if let Some(expected) = expected
                        && expected != *actual
                    {
                        fail(format!("{name} {actual:#x}, expected {expected:#x}"));
                    }
                }
            }
            (
                Self::MemrefOutput { expect, .. } | Self::MemrefInout { expect, .. },
                OutParam::Memref { data, size },
            ) => {
                if let Some(expected) = expect.expect_size
                    && expected != *size
                {
                    fail(format!("size {size}, expected {expected}"));
                }
                if let Some(expected) = &expect.expect_data_base64
                    && *data != decode_base64(expected)
                {
                    fail(format!("data {}, expected {expected}", encode_base64(data)));
                }
            }
            (Self::ValueOutput { expect } | Self::ValueInout { expect, .. }, OutParam::None)
                if expect.expect_value_a.is_some() || expect.expect_value_b.is_some() =>
            {
                fail("no output".into());
            }
            (
                Self::MemrefOutput { expect, .. } | Self::MemrefInout { expect, .. },
                OutParam::None,
            ) if expect.expect_size.is_some() || expect.expect_data_base64.is_some() => {
                fail("no output".into());
            }
            _ => {}
        }
    }
}

fn encode_base64(data: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(data)
}

fn decode_base64(data_base64: &str) -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(data_base64)
        .expect("Failed to decode base64 data")
}
