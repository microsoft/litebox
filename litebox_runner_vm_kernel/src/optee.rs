// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Test driver. The first boot module is a tar with `runner.elf`,
//! `ldelf.elf`, `ta.elf` (syscall-rewritten), and optionally `cmds.json`;
//! without it, a session is opened and closed twice.
//!
//! One TA instance at a time, in its own runner process: a new process once
//! the instance ends, which is when its last session closes (unless the TA
//! is single-instance and keep-alive). Only the TA header is checked, not its
//! signature, so a TA can claim any UUID and its derived keys.
//!
//! `cmds.json` is the format of
//! `litebox_runner_optee_on_linux_userland/tests/*-cmds.json`. Every command
//! must succeed; TA outputs are logged, not checked.

use alloc::string::String;
use alloc::vec::Vec;
use litebox_bootloader::handoff::BootInfo;
use litebox_common_optee::{TeeLogin, TeeResult};
use litebox_common_vm_abi::IDENTITY_LEN;
use litebox_platform_vm_kernel::{KERNEL_OFFSET, VmKernel};
use litebox_shim_vm_kernel::optee::{
    self, Completion, EntryFunc, InParam, Invocation, LDELF_IMAGE, NUM_PARAMS, OutParam, TA_IMAGE,
};
use litebox_shim_vm_kernel::{Process, ProcessConfig};
use serde::Deserialize;
use zerocopy::IntoBytes as _;

struct Payload {
    runner: &'static [u8],
    ldelf: &'static [u8],
    ta: &'static [u8],
    command_sequence: Option<&'static str>,
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

    let (mut runner, mut ldelf, mut ta, mut command_sequence) = (None, None, None, None);
    for entry in archive.entries() {
        let filename = entry.filename();
        let Ok(name) = filename.as_str() else {
            continue;
        };
        let bytes: &'static [u8] = entry.data();
        match name.trim_start_matches("./") {
            "runner.elf" => runner = Some(bytes),
            "ldelf.elf" => ldelf = Some(bytes),
            "ta.elf" => ta = Some(bytes),
            "cmds.json" => {
                command_sequence =
                    Some(core::str::from_utf8(bytes).map_err(|_| "cmds.json is not UTF-8")?);
            }
            _ => {}
        }
    }
    Ok(Payload {
        runner: runner.ok_or("payload has no runner.elf")?,
        ldelf: ldelf.ok_or("payload has no ldelf.elf")?,
        ta: ta.ok_or("payload has no ta.elf")?,
        command_sequence,
    })
}

/// # Panics
///
/// On any failure, including a TA result other than success.
pub fn run(platform: &'static VmKernel, info: &BootInfo, tsc_khz: u64) {
    let payload = payload(info).unwrap_or_else(|e| panic!("payload: {e}"));
    let head = litebox_common_optee::parse_ta_head(payload.ta).expect("malformed TA header");
    let mut identity = [0u8; IDENTITY_LEN];
    identity[..16].copy_from_slice(head.uuid.as_bytes());
    let keep_alive = head.flags.is_single_instance() && head.flags.is_keep_alive();
    let mut images = [&[][..]; 2];
    images[LDELF_IMAGE] = payload.ldelf;
    images[TA_IMAGE] = payload.ta;
    let config = ProcessConfig {
        runner: payload.runner,
        images: &images,
        identity,
        tsc_khz,
    };
    let broker_core = crate::broker::core();
    let spawn = || {
        let mut process = Process::spawn(platform, broker_core.clone(), &config)
            .unwrap_or_else(|e| panic!("spawn: {e:?}"));
        process
            .start()
            .unwrap_or_else(|dead| panic!("the runner died starting: {dead:?}"));
        process
    };

    let commands: Vec<TaCommand> = match payload.command_sequence {
        Some(json) => serde_json::from_str(json).expect("malformed cmds.json"),
        None => alloc::vec![
            TaCommand::new(TaEntryFunc::OpenSession),
            TaCommand::new(TaEntryFunc::CloseSession),
            TaCommand::new(TaEntryFunc::OpenSession),
            TaCommand::new(TaEntryFunc::CloseSession),
        ],
    };
    // The live instance's process and session count.
    let mut instance: Option<(Process, usize)> = None;
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
                .map_or([0; 16], parse_uuid_or_panic),
            params: cmd.params(),
        };
        let (process, sessions) = instance.get_or_insert_with(|| (spawn(), 0));
        let completion = optee::call(process, invocation)
            .unwrap_or_else(|dead| panic!("command {index} ({func:?}): the runner died: {dead:?}"));
        assert!(
            completion.result == u32::from(TeeResult::Success),
            "command {index} ({func:?}): result {:#x} (origin {})",
            completion.result,
            completion.origin
        );
        match func {
            EntryFunc::OpenSession => {
                *sessions += 1;
                session = completion.session;
                litebox_util_log::info!(session:% = session; "session opened");
            }
            EntryFunc::CloseSession => *sessions = sessions.saturating_sub(1),
            EntryFunc::InvokeCommand => {}
        }
        log_outputs(&completion);
        if *sessions == 0 && !keep_alive {
            instance = None;
        }
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
