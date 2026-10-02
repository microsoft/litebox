// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Test driver. The first boot module is a tar with `runner.elf`,
//! `ldelf.elf`, TAs as `tas/<name>.elf` (rewritten or not), and optionally
//! `cmds.json`; without it, a session to the only TA is opened and closed
//! twice. Only TA headers are checked, not signatures, so a TA can claim any
//! UUID and its derived keys.
//!
//! `cmds.json` is the format of
//! `litebox_runner_optee_on_linux_userland/tests/*-cmds.json` plus optional:
//! - `ta`: the `open_session` target; required with more than one TA.
//! - `session`: a label (default `default`).
//! - `expect_result`: default success.
//! - `expect_instances`: live instances after the command.
//!
//! TA outputs are logged, not checked.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use litebox_bootloader::handoff::BootInfo;
use litebox_common_optee::{TeeLogin, TeeResult};
use litebox_common_vm_abi::IDENTITY_LEN;
use litebox_platform_vm_kernel::{KERNEL_OFFSET, VmKernel};
use litebox_shim_vm_kernel::optee::ta_manager::{InstancePolicy, TaManager, TaUuid};
use litebox_shim_vm_kernel::optee::{
    Completion, EntryFunc, InParam, Invocation, LDELF_IMAGE, NUM_PARAMS, OutParam, TA_IMAGE,
};
use litebox_shim_vm_kernel::{Dead, Process, ProcessConfig, SpawnError};
use serde::Deserialize;
use zerocopy::IntoBytes as _;

const DEFAULT_SESSION: &str = "default";

struct Ta {
    name: &'static str,
    uuid: TaUuid,
    policy: InstancePolicy,
    image: &'static [u8],
}

struct Payload {
    runner: &'static [u8],
    ldelf: &'static [u8],
    tas: Vec<Ta>,
    command_sequence: Option<&'static str>,
}

fn ta(name: &'static str, image: &'static [u8]) -> Result<Ta, &'static str> {
    // Only the header is checked; signatures are not verified.
    let head = litebox_common_optee::parse_ta_head(image).ok_or("malformed TA header")?;
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(head.uuid.as_bytes());
    Ok(Ta {
        name,
        uuid,
        policy: InstancePolicy {
            single_instance: head.flags.is_single_instance(),
            multi_session: head.flags.is_multi_session(),
            keep_alive: head.flags.is_keep_alive(),
        },
        image,
    })
}

fn payload(info: &BootInfo) -> Result<Payload, &'static str> {
    let module = info
        .modules
        .first()
        .ok_or("no payload module (pass -initrd)")?;
    let len = usize::try_from(module.end - module.start).unwrap();
    // Safety: boot modules are excluded from the heap and stay mapped at
    // `PA + KERNEL_OFFSET` for the kernel's lifetime.
    let data: &'static [u8] =
        unsafe { core::slice::from_raw_parts((module.start + KERNEL_OFFSET) as *const u8, len) };
    let archive = tar_no_std::TarArchiveRef::new(data).map_err(|_| "payload is not a tar")?;

    let (mut runner, mut ldelf, mut command_sequence) = (None, None, None);
    let mut tas = Vec::new();
    for entry in archive.entries() {
        let filename = entry.filename();
        let Ok(name) = filename.as_str() else {
            continue;
        };
        // `tar_no_std` names do not outlive the entry.
        let name: &'static str = alloc::boxed::Box::leak(name.into());
        let bytes: &'static [u8] = entry.data();
        match name.trim_start_matches("./") {
            "runner.elf" => runner = Some(bytes),
            "ldelf.elf" => ldelf = Some(bytes),
            "cmds.json" => {
                command_sequence =
                    Some(core::str::from_utf8(bytes).map_err(|_| "cmds.json is not UTF-8")?);
            }
            path => {
                if let Some(ta_name) = path
                    .strip_prefix("tas/")
                    .and_then(|p| p.strip_suffix(".elf"))
                {
                    tas.push(ta(ta_name, bytes)?);
                }
            }
        }
    }
    if tas.is_empty() {
        return Err("payload has no tas/<name>.elf");
    }
    Ok(Payload {
        runner: runner.ok_or("payload has no runner.elf")?,
        ldelf: ldelf.ok_or("payload has no ldelf.elf")?,
        tas,
        command_sequence,
    })
}

#[derive(Debug)]
#[expect(dead_code, reason = "only for `Debug`")]
enum StartError {
    UnknownTa,
    Spawn(SpawnError),
    Start(Dead),
}

/// # Panics
///
/// On any failure, including an unexpected TA result.
pub fn run(platform: &'static VmKernel, info: &BootInfo, tsc_khz: u64) {
    let payload = payload(info).unwrap_or_else(|e| panic!("payload: {e}"));
    let broker_core = crate::broker::core();
    let (runner, ldelf) = (payload.runner, payload.ldelf);
    let ta_images: BTreeMap<TaUuid, &'static [u8]> =
        payload.tas.iter().map(|ta| (ta.uuid, ta.image)).collect();
    let mut manager = TaManager::new(move |uuid: &TaUuid| {
        let ta = ta_images.get(uuid).ok_or(StartError::UnknownTa)?;
        let mut images = [&[][..]; 2];
        images[LDELF_IMAGE] = ldelf;
        images[TA_IMAGE] = ta;
        let mut identity = [0u8; IDENTITY_LEN];
        identity[..uuid.len()].copy_from_slice(uuid);
        let mut process = Process::spawn(
            platform,
            broker_core.clone(),
            &ProcessConfig {
                runner,
                images: &images,
                identity,
                tsc_khz,
            },
        )
        .map_err(StartError::Spawn)?;
        process.start().map_err(StartError::Start)?;
        Ok::<_, StartError>(process)
    });
    for ta in &payload.tas {
        litebox_util_log::info!(name:% = ta.name, policy:? = ta.policy; "TA");
        manager.register(ta.uuid, ta.policy);
    }

    let commands: Vec<TaCommand> = match payload.command_sequence {
        Some(json) => serde_json::from_str(json).expect("malformed cmds.json"),
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
        let uuid = if func == EntryFunc::OpenSession {
            target_ta(&payload.tas, cmd.ta.as_deref()).uuid
        } else {
            [0; 16]
        };
        let invocation = Invocation {
            func,
            session: if func == EntryFunc::OpenSession {
                0
            } else {
                // An unknown label means an unknown session.
                sessions.get(label).copied().unwrap_or(u32::MAX)
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
                .map_or([0; 16], parse_uuid_or_panic),
            params: cmd.params(),
        };
        let completion = manager.call(&uuid, invocation);
        let expected = cmd.expect_result.unwrap_or(TeeResult::Success.into());
        assert!(
            completion.result == expected,
            "command {index} ({func:?}, session {label:?}): result {:#x} (origin {}), expected {expected:#x}",
            completion.result,
            completion.origin
        );
        match func {
            EntryFunc::OpenSession if completion.result == 0 => {
                sessions.insert(label.into(), completion.session);
                litebox_util_log::info!(session:% = completion.session, label:% = label; "session opened");
            }
            EntryFunc::CloseSession => {
                sessions.remove(label);
            }
            _ => {}
        }
        if let Some(expected) = cmd.expect_instances {
            assert_eq!(
                manager.instance_count(),
                expected,
                "command {index}: live TA instances"
            );
        }
        log_outputs(&completion);
    }
}

fn target_ta<'a>(tas: &'a [Ta], name: Option<&str>) -> &'a Ta {
    if let Some(name) = name {
        tas.iter()
            .find(|ta| ta.name == name)
            .unwrap_or_else(|| panic!("no TA named {name:?}"))
    } else {
        assert!(tas.len() == 1, "`ta` is required with several TAs");
        &tas[0]
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

/// To `TEE_UUID` memory layout, as `TeeUuid::from_bytes` interprets the
/// string.
fn parse_uuid_or_panic(s: &str) -> [u8; 16] {
    let hex: String = s.chars().filter(|&c| c != '-').collect();
    assert!(
        hex.len() == 32 && hex.bytes().all(|b| b.is_ascii_hexdigit()),
        "client uuid must be 32 hex digits: {s:?}"
    );
    let mut bytes = [0u8; 16];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("checked hex digits");
    }
    let uuid = litebox_common_optee::TeeUuid::from_bytes(bytes);
    let mut out = [0u8; 16];
    out.copy_from_slice(uuid.as_bytes());
    out
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
