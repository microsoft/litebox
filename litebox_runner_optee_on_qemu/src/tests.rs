// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! User-memory checks and JSON-driven TA commands. TA outputs are logged,
//! not checked; a TA error fails the run.

use alloc::string::String;
use alloc::vec::Vec;
use litebox::platform::RawConstPointer;
use litebox::utils::TruncateExt;
use litebox_common_optee::{
    TeeIdentity, TeeLogin, TeeParamType, TeeUuid, UteeEntryFunc, UteeParamOwned, UteeParams,
};
use litebox_platform_vm_kernel::VmKernel;
use litebox_shim_optee::{LoadedProgram, UserConstPtr};
use serde::Deserialize;

pub fn check_user_memory_protection(platform: &VmKernel) {
    use litebox::platform::{
        PageManagementProvider, RawMutPointer as _,
        page_mgmt::{FixedAddressBehavior, MemoryRegionPermissions as Permissions},
    };
    use litebox_common_linux::vmem::PAGE_SIZE;
    use litebox_platform_vm_kernel::AddressSpaceId;

    let id = platform.create_address_space();
    // Safety: no user references exist; this private address space is used only here.
    unsafe { platform.switch_address_space(id) }.unwrap();
    let range = 0x1_0000..0x1_0000 + PAGE_SIZE;
    let writable = Permissions::READ | Permissions::WRITE;
    // Safety: this aligned user range is unused in the private address space.
    let reservation = unsafe {
        <VmKernel as PageManagementProvider<PAGE_SIZE>>::reserve_and_commit_pages(
            platform,
            core::iter::empty,
            range.clone(),
            writable,
            false,
            true,
            FixedAddressBehavior::NoReplace,
        )
    }
    .unwrap();
    let ptr = <VmKernel as litebox::platform::RawPointerProvider>::RawMutPointer::<u8>::from_usize(
        range.start,
    );
    assert_eq!(ptr.write_at_offset(0, 0x5a), Some(()));
    for _ in 0..2 {
        // Safety: no borrowed user references; only fallible copies access the range.
        unsafe {
            <VmKernel as PageManagementProvider<PAGE_SIZE>>::protect_pages(
                platform,
                || core::iter::once(&reservation),
                range.clone(),
                Permissions::empty(),
            )
        }
        .unwrap();
        assert_eq!(ptr.read_at_offset(0), None);
        assert_eq!(ptr.write_at_offset(0, 0xa5), None);
        // Safety: as above; restore access to the same owned frame.
        unsafe {
            <VmKernel as PageManagementProvider<PAGE_SIZE>>::protect_pages(
                platform,
                || core::iter::once(&reservation),
                range.clone(),
                writable,
            )
        }
        .unwrap();
        assert_eq!(ptr.read_at_offset(0), Some(0x5a));
    }
    // Safety: no user references remain and the pointer is not used afterward.
    unsafe {
        <VmKernel as PageManagementProvider<PAGE_SIZE>>::protect_pages(
            platform,
            || core::iter::once(&reservation),
            range,
            Permissions::empty(),
        )
        .unwrap();
        platform
            .switch_address_space(AddressSpaceId::KERNEL)
            .unwrap();
        platform.unregister_address_space(id).unwrap();
    }
}

pub fn run_ta_with_test_commands(
    shim: &litebox_shim_optee::OpteeShim<VmKernel>,
    ldelf_bin: &[u8],
    ta_bin: &[u8],
    json_str: &str,
) {
    let ta_commands: Vec<TaCommandBase64> = serde_json::from_str(json_str).unwrap();
    let ta_head =
        litebox_common_optee::parse_ta_head(ta_bin).expect("Failed to parse TA header from ta_bin");
    assert!(shim.store_ta_bin(&ta_head.uuid, ta_bin));
    let mut ta_info: Option<LoadedProgram<VmKernel>> = None;
    let mut session_id: Option<u32> = None;

    for cmd in ta_commands {
        assert!(
            (cmd.args.len() <= UteeParamOwned::TEE_NUM_PARAMS),
            "ta_command has more than four arguments."
        );

        let mut params = [const { UteeParamOwned::None }; UteeParamOwned::TEE_NUM_PARAMS];
        for (param, arg) in params.iter_mut().zip(&cmd.args) {
            *param = arg.to_utee_params_owned();
        }

        let func_id = UteeEntryFunc::from(cmd.func_id);
        match cmd.func_id {
            TaEntryFunc::CloseSession => continue,
            TaEntryFunc::OpenSession => {
                let mut session_token = shim
                    .session_manager()
                    .try_acquire_open_session_token()
                    .unwrap();
                let open_session_id = session_token.session_id().unwrap();
                session_id = Some(open_session_id);
                let client_identity = cmd.client_identity.as_ref().map_or(
                    TeeIdentity {
                        login: TeeLogin::User,
                        uuid: TeeUuid::NIL,
                    },
                    ClientIdentityJson::to_tee_identity,
                );
                shim.session_manager()
                    .set_session_client_identity(open_session_id, Some(client_identity));
                let loaded = shim
                    .load_ldelf(ldelf_bin, ta_head.uuid)
                    .unwrap_or_else(|e| panic!("Failed to load TA: {e:?}"));
                let info = ta_info.insert(loaded);
                let mut ctx = litebox_common_linux::PtRegs::default();
                // Safety: the platform is set up, and threads run one at a time.
                unsafe {
                    litebox_platform_vm_kernel::run_thread_ref(
                        info.entrypoints.as_ref().unwrap(),
                        &mut ctx,
                    );
                }
                assert!(
                    ctx.rax == 0,
                    "ldelf exits with error: return_code={:#x}",
                    ctx.rax
                );
                // Keep the session ID and client identity across commands.
                session_token.disarm();
            }
            TaEntryFunc::InvokeCommand => {}
        }

        if let Some(info) = ta_info.as_mut() {
            let session_id = session_id.expect("session id set by OpenSession");
            info.entrypoints
                .as_ref()
                .unwrap()
                .load_ta_context(
                    params.as_slice(),
                    session_id,
                    func_id as u32,
                    Some(cmd.cmd_id),
                )
                .unwrap_or_else(|e| panic!("Failed to load TA context: {e:?}"));
            let mut ctx = litebox_common_linux::PtRegs::default();
            // Safety: the platform is set up, and threads run one at a time.
            unsafe {
                litebox_platform_vm_kernel::reenter_thread_ref(
                    info.entrypoints.as_ref().unwrap(),
                    &mut ctx,
                );
            }
            assert!(
                ctx.rax == 0,
                "TA exits with error: return_code={:#x}",
                ctx.rax
            );
            if let Some(params_address) = info.params_address {
                let ptr = UserConstPtr::<VmKernel, UteeParams>::from_usize(params_address);
                let params = ptr.read_at_offset(0).expect("Failed to read UteeParams");
                handle_ta_command_output(&params);
            }
        }
    }
}

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
                }
            }
            TeeParamType::MemrefOutput | TeeParamType::MemrefInout => {
                if let Ok(Some((addr, len))) = params.get_values(idx) {
                    let len: usize = len.trunc();
                    let ptr = UserConstPtr::<VmKernel, u8>::from_usize(addr.trunc());
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
                }
            }
            _ => {}
        }
    }
}

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
    assert!(
        hex.len() == 32 && hex.bytes().all(|b| b.is_ascii_hexdigit()),
        "client uuid must be 32 hex digits: {s:?}"
    );
    let mut bytes = [0u8; 16];
    for (i, byte) in bytes.iter_mut().enumerate() {
        // ASCII, so every index is a char boundary.
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("checked hex digits");
    }
    TeeUuid::from_bytes(bytes)
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaEntryFunc {
    OpenSession,
    CloseSession,
    InvokeCommand,
}

impl From<TaEntryFunc> for UteeEntryFunc {
    fn from(func: TaEntryFunc) -> Self {
        match func {
            TaEntryFunc::OpenSession => UteeEntryFunc::OpenSession,
            TaEntryFunc::CloseSession => UteeEntryFunc::CloseSession,
            TaEntryFunc::InvokeCommand => UteeEntryFunc::InvokeCommand,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(tag = "param_type", rename_all = "snake_case")]
enum TaCommandParamsBase64 {
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

impl TaCommandParamsBase64 {
    pub fn to_utee_params_owned(&self) -> UteeParamOwned {
        match self {
            TaCommandParamsBase64::ValueInput { value_a, value_b } => UteeParamOwned::ValueInput {
                value_a: *value_a,
                value_b: *value_b,
            },
            TaCommandParamsBase64::ValueOutput => UteeParamOwned::ValueOutput,
            TaCommandParamsBase64::ValueInout { value_a, value_b } => UteeParamOwned::ValueInout {
                value_a: *value_a,
                value_b: *value_b,
            },
            TaCommandParamsBase64::MemrefInput { data_base64 } => UteeParamOwned::MemrefInput {
                data: Some(decode_base64(data_base64).into_boxed_slice()),
            },
            TaCommandParamsBase64::MemrefOutput { buffer_size } => UteeParamOwned::MemrefOutput {
                buffer_size: usize::try_from(*buffer_size).unwrap(),
            },
            TaCommandParamsBase64::MemrefInout {
                data_base64,
                buffer_size,
            } => {
                let decoded_data = decode_base64(data_base64);
                let buffer_size = usize::try_from(*buffer_size).unwrap();
                assert!(
                    buffer_size >= decoded_data.len(),
                    "Buffer size is smaller than input data size"
                );
                UteeParamOwned::MemrefInout {
                    data: Some(decoded_data.into_boxed_slice()),
                    buffer_size,
                }
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
