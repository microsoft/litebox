// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! OP-TEE's message passing is a bit complex because it involves with multiple actors
//! (normal world: client app and driver; secure world: OP-TEE OS and TAs),
//! consists multiple layers, and relies on shared memory references (i.e., no serialization).
//!
//! Since the normal world is out of LiteBox's scope, the OP-TEE shim starts with handling
//! an OP-TEE SMC call from the normal-world OP-TEE driver which consists of
//! up to nine register values. By checking the SMC function ID, the shim determines whether
//! it is for passing an OP-TEE message or a pure SMC function call (e.g., get OP-TEE OS
//! version). If it is for passing an OP-TEE message/command, the shim accesses a normal world
//! physical address containing `OpteeMsgArgs` structure (the address is contained in
//! the SMC call arguments). This `OpteeMsgArgs` structure may contain references to normal
//! world physical addresses to exchange a large amount of data. Also, like the OP-TEE
//! SMC call, some OP-TEE messages/commands target OP-TEE shim not TAs (e.g., register
//! shared memory).
use crate::{NormalWorldConstPtr, NormalWorldMutPtr};
use alloc::{boxed::Box, vec::Vec};
use hashbrown::HashMap;
use litebox::{mm::linux::PAGE_SIZE, utils::TruncateExt};
use litebox_common_linux::vmap::{PhysPageAddr, PhysPointerError};
use litebox_common_optee::{
    OpteeMessageCommand, OpteeMsgArgs, OpteeMsgAttrType, OpteeMsgParamRmem, OpteeMsgParamTmem,
    OpteeMsgParamValue, OpteeSecureWorldCapabilities, OpteeSmcArgs, OpteeSmcFunction,
    OpteeSmcResult, OpteeSmcReturnCode, TeeIdentity, TeeLogin, TeeOrigin, TeeParamType, TeeResult,
    TeeUuid, UteeEntryFunc, UteeParamOwned, UteeParams,
};
use once_cell::race::OnceBox;

// OP-TEE version and build info (2.0)
// TODO: Consider replacing it with our own version info
const OPTEE_MSG_REVISION_MAJOR: usize = 2;
const OPTEE_MSG_REVISION_MINOR: usize = 0;
const OPTEE_MSG_BUILD_ID: usize = 0;

// This UID is from OP-TEE OS
// TODO: Consider replacing it with our own UID
const OPTEE_MSG_UID_0: u32 = 0x384f_b3e0;
const OPTEE_MSG_UID_1: u32 = 0xe7f8_11e3;
const OPTEE_MSG_UID_2: u32 = 0xaf63_0002;
const OPTEE_MSG_UID_3: u32 = 0xa5d5_c51b;

// This is the UUID of OP-TEE Trusted OS
// TODO: Consider replacing it with our own UUID
const OPTEE_MSG_OS_OPTEE_UUID_0: u32 = 0x4861_78e0;
const OPTEE_MSG_OS_OPTEE_UUID_1: u32 = 0xe7f8_11e3;
const OPTEE_MSG_OS_OPTEE_UUID_2: u32 = 0xbc5e_0002;
const OPTEE_MSG_OS_OPTEE_UUID_3: u32 = 0xa5d5_c51b;

// We do not support notification for now
const MAX_NOTIF_VALUE: usize = 0;
const NUM_RPC_PARMS: usize = 4;

#[inline]
fn page_align_down(address: u64) -> u64 {
    address & !(PAGE_SIZE as u64 - 1)
}

#[inline]
fn page_align_up(len: u64) -> u64 {
    len.next_multiple_of(PAGE_SIZE as u64)
}

/// This function handles `OpteeSmcArgs` passed from the normal world (VTL0) via an OP-TEE SMC call.
/// It returns an `OpteeSmcResult` representing the result of the SMC call or `OpteeMsgArgs` it contains
/// if the SMC call involves with an OP-TEE message which should be handled by
/// `handle_optee_msg_args` or `handle_ta_request`.
pub fn handle_optee_smc_args(
    smc: &mut OpteeSmcArgs,
) -> Result<OpteeSmcResult<'_>, OpteeSmcReturnCode> {
    let func_id = smc.func_id()?;
    #[cfg(debug_assertions)]
    litebox::log_println!(
        litebox_platform_multiplex::platform(),
        "OP-TEE SMC Function: {:?}",
        func_id
    );
    match func_id {
        OpteeSmcFunction::CallWithArg
        | OpteeSmcFunction::CallWithRpcArg
        | OpteeSmcFunction::CallWithRegdArg => {
            let msg_args_addr = smc.optee_msg_args_phys_addr()?;
            let msg_args_addr: usize = msg_args_addr.truncate();
            let mut ptr = NormalWorldConstPtr::<OpteeMsgArgs, PAGE_SIZE>::with_usize(msg_args_addr)
                .map_err(|_| OpteeSmcReturnCode::EBadAddr)?;
            let msg_args =
                unsafe { ptr.read_at_offset(0) }.map_err(|_| OpteeSmcReturnCode::EBadAddr)?;
            Ok(OpteeSmcResult::CallWithArg {
                msg_args: Box::new(*msg_args),
            })
        }
        OpteeSmcFunction::ExchangeCapabilities => {
            // TODO: update the below when we support more features
            let default_cap = OpteeSecureWorldCapabilities::DYNAMIC_SHM
                | OpteeSecureWorldCapabilities::MEMREF_NULL
                | OpteeSecureWorldCapabilities::RPC_ARG;
            Ok(OpteeSmcResult::ExchangeCapabilities {
                status: OpteeSmcReturnCode::Ok,
                capabilities: default_cap,
                max_notif_value: MAX_NOTIF_VALUE,
                data: NUM_RPC_PARMS,
            })
        }
        OpteeSmcFunction::DisableShmCache => {
            // Currently, we do not support this feature.
            Ok(OpteeSmcResult::DisableShmCache {
                status: OpteeSmcReturnCode::ENotAvail,
                shm_upper32: 0,
                shm_lower32: 0,
            })
        }
        OpteeSmcFunction::GetOsUuid => Ok(OpteeSmcResult::Uuid {
            data: &[
                OPTEE_MSG_OS_OPTEE_UUID_0,
                OPTEE_MSG_OS_OPTEE_UUID_1,
                OPTEE_MSG_OS_OPTEE_UUID_2,
                OPTEE_MSG_OS_OPTEE_UUID_3,
            ],
        }),
        OpteeSmcFunction::CallsUid => Ok(OpteeSmcResult::Uuid {
            data: &[
                OPTEE_MSG_UID_0,
                OPTEE_MSG_UID_1,
                OPTEE_MSG_UID_2,
                OPTEE_MSG_UID_3,
            ],
        }),
        OpteeSmcFunction::GetOsRevision => Ok(OpteeSmcResult::OsRevision {
            major: OPTEE_MSG_REVISION_MAJOR,
            minor: OPTEE_MSG_REVISION_MINOR,
            build_id: OPTEE_MSG_BUILD_ID,
        }),
        OpteeSmcFunction::CallsRevision => Ok(OpteeSmcResult::Revision {
            major: OPTEE_MSG_REVISION_MAJOR,
            minor: OPTEE_MSG_REVISION_MINOR,
        }),
        _ => Err(OpteeSmcReturnCode::UnknownFunction),
    }
}

/// This function handles an OP-TEE message contained in `OpteeMsgArgs`.
/// Currently, it only handles shared memory registration and unregistration.
/// If an OP-TEE message involves with a TA request, it simply returns
/// `Err(OpteeSmcReturnCode::Ok)` while expecting that the caller will handle
/// the message with `handle_ta_request`.
pub fn handle_optee_msg_args(msg_args: &OpteeMsgArgs) -> Result<(), OpteeSmcReturnCode> {
    msg_args.validate()?;
    match msg_args.cmd {
        OpteeMessageCommand::RegisterShm => {
            let tmem = msg_args.get_param_tmem(0)?;
            if tmem.buf_ptr == 0 || tmem.size == 0 || tmem.shm_ref == 0 {
                return Err(OpteeSmcReturnCode::EBadAddr);
            }
            // `tmem.buf_ptr` encodes two different information:
            // - The physical page address of the first `ShmRefPagesData`
            // - The page offset of the first shared memory page (`pages_list[0]`)
            let shm_ref_pages_data_phys_addr = page_align_down(tmem.buf_ptr);
            let page_offset = tmem.buf_ptr - shm_ref_pages_data_phys_addr;
            let aligned_size = page_align_up(page_offset + tmem.size);
            shm_ref_map().register_shm(
                shm_ref_pages_data_phys_addr,
                page_offset,
                aligned_size,
                tmem.shm_ref,
            )?;
        }
        OpteeMessageCommand::UnregisterShm => {
            let rmem = msg_args.get_param_rmem(0)?;
            if rmem.shm_ref == 0 {
                return Err(OpteeSmcReturnCode::EBadAddr);
            }
            shm_ref_map()
                .remove(rmem.shm_ref)
                .ok_or(OpteeSmcReturnCode::EBadAddr)?;
        }
        OpteeMessageCommand::OpenSession
        | OpteeMessageCommand::InvokeCommand
        | OpteeMessageCommand::CloseSession => return Err(OpteeSmcReturnCode::Ok),
        _ => {
            todo!("Unimplemented OpteeMessageCommand: {:?}", msg_args.cmd);
        }
    }
    Ok(())
}

/// TA request information extracted from an OP-TEE message.
///
/// In addition to standard TA information (i.e., TA UUID, session ID, command ID,
/// and parameters), it contains shared memory information (`out_shm_info`) to
/// write back output data to the normal world once the TA execution is done.
pub struct TaRequestInfo<const ALIGN: usize> {
    pub uuid: Option<TeeUuid>,
    pub client_identity: Option<TeeIdentity>,
    pub session: u32,
    pub entry_func: UteeEntryFunc,
    pub cmd_id: u32,
    pub params: [UteeParamOwned; UteeParamOwned::TEE_NUM_PARAMS],
    pub out_shm_info: [Option<ShmInfo<ALIGN>>; UteeParamOwned::TEE_NUM_PARAMS],
}

/// This function decodes a TA request contained in `OpteeMsgArgs`.
///
/// It copies the entire parameter data from the normal world shared memory into the secure world's
/// memory to create `UteeParamOwned` structures to avoid potential data corruption during TA
/// execution.
///
/// # Panics
///
/// Panics if any conversion from `u64` to `usize` fails. OP-TEE shim doesn't support a 32-bit environment.
pub fn decode_ta_request(
    msg_args: &OpteeMsgArgs,
) -> Result<TaRequestInfo<PAGE_SIZE>, OpteeSmcReturnCode> {
    let ta_entry_func: UteeEntryFunc = msg_args.cmd.try_into()?;
    let (ta_uuid, client_identity, skip): (Option<TeeUuid>, Option<TeeIdentity>, usize) =
        if ta_entry_func == UteeEntryFunc::OpenSession {
            // If it is an OpenSession request, extract UUIDs and login from params[0] and params[1]
            // Based on observed Linux kernel behavior:
            // - params[0].a/b = TA UUID (two little-endian u64 values)
            // - params[1].a/b = client UUID (two little-endian u64 values)
            // - params[1].c = client login type (TEE_LOGIN_*)
            let param0 = msg_args.get_param_value(0)?;
            let ta_data = [param0.a, param0.b];

            let param1 = msg_args.get_param_value(1)?;
            let client_data = [param1.a, param1.b];
            let login: u32 = param1.c.truncate();
            let login = TeeLogin::try_from(login).unwrap_or(TeeLogin::Public);

            // Skip the first two parameters as they convey TA and client UUIDs
            (
                Some(TeeUuid::from_u64_array(ta_data)),
                Some(TeeIdentity {
                    login,
                    uuid: TeeUuid::from_u64_array(client_data),
                }),
                2,
            )
        } else {
            (None, None, 0)
        };

    let mut ta_req_info = TaRequestInfo {
        uuid: ta_uuid,
        client_identity,
        session: msg_args.session,
        entry_func: ta_entry_func,
        cmd_id: msg_args.func,
        params: [const { UteeParamOwned::None }; UteeParamOwned::TEE_NUM_PARAMS],
        out_shm_info: [const { None }; UteeParamOwned::TEE_NUM_PARAMS],
    };

    let num_params = msg_args.num_params as usize;
    for (i, param) in msg_args
        .params
        .iter()
        .take(num_params)
        .skip(skip)
        .enumerate()
    {
        ta_req_info.params[i] = match param.attr_type() {
            OpteeMsgAttrType::None => UteeParamOwned::None,
            OpteeMsgAttrType::ValueInput => {
                let value = param.get_param_value().ok_or(OpteeSmcReturnCode::EBadCmd)?;
                UteeParamOwned::ValueInput {
                    value_a: value.a,
                    value_b: value.b,
                }
            }
            OpteeMsgAttrType::ValueOutput => UteeParamOwned::ValueOutput,
            OpteeMsgAttrType::ValueInout => {
                let value = param.get_param_value().ok_or(OpteeSmcReturnCode::EBadCmd)?;
                UteeParamOwned::ValueInout {
                    value_a: value.a,
                    value_b: value.b,
                }
            }
            OpteeMsgAttrType::TmemInput => {
                let tmem = param.get_param_tmem().ok_or(OpteeSmcReturnCode::EBadCmd)?;
                let shm_info = get_shm_info_from_optee_msg_param_tmem(tmem)?;
                let data_size = tmem.size.truncate();
                build_memref_input(&shm_info, data_size)?
            }
            OpteeMsgAttrType::RmemInput => {
                let rmem = param.get_param_rmem().ok_or(OpteeSmcReturnCode::EBadCmd)?;
                let shm_info = get_shm_info_from_optee_msg_param_rmem(rmem)?;
                let data_size = rmem.size.truncate();
                build_memref_input(&shm_info, data_size)?
            }
            OpteeMsgAttrType::TmemOutput => {
                let tmem = param.get_param_tmem().ok_or(OpteeSmcReturnCode::EBadCmd)?;
                let shm_info = get_shm_info_from_optee_msg_param_tmem(tmem)?;
                let buffer_size = tmem.size.truncate();

                ta_req_info.out_shm_info[i] = Some(shm_info);
                UteeParamOwned::MemrefOutput { buffer_size }
            }
            OpteeMsgAttrType::RmemOutput => {
                let rmem = param.get_param_rmem().ok_or(OpteeSmcReturnCode::EBadCmd)?;
                let shm_info = get_shm_info_from_optee_msg_param_rmem(rmem)?;
                let buffer_size = rmem.size.truncate();

                ta_req_info.out_shm_info[i] = Some(shm_info);
                UteeParamOwned::MemrefOutput { buffer_size }
            }
            OpteeMsgAttrType::TmemInout => {
                let tmem = param.get_param_tmem().ok_or(OpteeSmcReturnCode::EBadCmd)?;
                let shm_info = get_shm_info_from_optee_msg_param_tmem(tmem)?;
                let buffer_size = tmem.size.truncate();

                ta_req_info.out_shm_info[i] = Some(shm_info.clone());
                build_memref_inout(&shm_info, buffer_size)?
            }
            OpteeMsgAttrType::RmemInout => {
                let rmem = param.get_param_rmem().ok_or(OpteeSmcReturnCode::EBadCmd)?;
                let shm_info = get_shm_info_from_optee_msg_param_rmem(rmem)?;
                let buffer_size = rmem.size.truncate();

                ta_req_info.out_shm_info[i] = Some(shm_info.clone());
                build_memref_inout(&shm_info, buffer_size)?
            }
            _ => return Err(OpteeSmcReturnCode::EBadCmd),
        };
    }

    Ok(ta_req_info)
}

#[inline]
fn build_memref_input(
    shm_info: &ShmInfo<PAGE_SIZE>,
    data_size: usize,
) -> Result<UteeParamOwned, OpteeSmcReturnCode> {
    let mut data = alloc::vec![0u8; data_size];
    read_data_from_shm(shm_info, &mut data)?;
    Ok(UteeParamOwned::MemrefInput { data: data.into() })
}

#[inline]
fn build_memref_inout(
    shm_info: &ShmInfo<PAGE_SIZE>,
    buffer_size: usize,
) -> Result<UteeParamOwned, OpteeSmcReturnCode> {
    let mut buffer = alloc::vec![0u8; buffer_size];
    read_data_from_shm(shm_info, &mut buffer)?;
    Ok(UteeParamOwned::MemrefInout {
        data: buffer.into(),
        buffer_size,
    })
}

/// This function updates the OP-TEE message arguments for returning from the secure world to the normal world.
///
/// It writes back TA execution outputs associated with shared memory references and updates
/// the `OpteeMsgArgs` structure to return value-based outputs.
/// `return_code` indicates the result of an OP-TEE request and `return_origin` indicates which component
/// generated the return code. `session_id` can be provided if this is for an OpenSession request.
/// `ta_params` is a reference to `UteeParams` structure that stores TA's output within its memory.
/// `ta_req_info` refers to the decoded TA request information including the normal world
/// shared memory addresses to write back output data.
pub fn update_optee_msg_args(
    return_code: TeeResult,
    return_origin: TeeOrigin,
    session_id: Option<u32>,
    ta_params: Option<&UteeParams>,
    ta_req_info: Option<&TaRequestInfo<PAGE_SIZE>>,
    msg_args: &mut OpteeMsgArgs,
) -> Result<(), OpteeSmcReturnCode> {
    msg_args.ret = return_code;
    msg_args.ret_origin = return_origin;
    if let Some(session_id) = session_id {
        msg_args.session = session_id;
    }

    let Some(ta_params) = ta_params else {
        return Ok(());
    };
    let Some(ta_req_info) = ta_req_info else {
        return Ok(());
    };
    for index in 0..UteeParams::TEE_NUM_PARAMS {
        let param_type = ta_params
            .get_type(index)
            .map_err(|_| OpteeSmcReturnCode::EBadAddr)?;
        match param_type {
            TeeParamType::ValueOutput | TeeParamType::ValueInout => {
                if let Ok(Some((value_a, value_b))) = ta_params.get_values(index) {
                    msg_args.set_param_value(
                        index,
                        OpteeMsgParamValue {
                            a: value_a,
                            b: value_b,
                            c: 0,
                        },
                    )?;
                }
            }
            TeeParamType::MemrefOutput | TeeParamType::MemrefInout => {
                if let Ok(Some((addr, len))) = ta_params.get_values(index) {
                    // SAFETY
                    // `addr` is expected to be a valid address of a TA and `addr + len` does not
                    // exceed the TA's memory region.
                    use litebox::platform::RawConstPointer;
                    let ptr = crate::UserConstPtr::<u8>::from_usize(addr.truncate());
                    let slice = ptr
                        .to_owned_slice(len.truncate())
                        .ok_or(OpteeSmcReturnCode::EBadAddr)?;

                    // Update the output size in msg_args
                    // For rmem/tmem params, size is at the same offset as value.b in the union
                    msg_args.set_param_memref_size(index, len)?;

                    if slice.is_empty() {
                        continue;
                    }
                    if let Some(out_shm_info) = &ta_req_info.out_shm_info[index] {
                        write_data_to_shm(out_shm_info, slice.as_ref())?;
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// A scatter-gather list of OP-TEE physical page addresses in the normal world (VTL0) to
/// share with the secure world (VTL1). Each [`ShmRefPagesData`] occupies one memory page
/// where `pages_list` contains a list of physical page addresses and `next_page_data`
/// contains the physical address of the next [`ShmRefPagesData`] if any. Entries of `pages_list`
/// and `next_page_data` contain zero if the list ends. These physical page addresses are
/// virtually contiguous in the normal world. All these address values must be page aligned.
///
/// `pages_data` from [Linux](https://elixir.bootlin.com/linux/v6.18.2/source/drivers/tee/optee/smc_abi.c#L409)
#[derive(Clone, Copy)]
#[repr(C)]
struct ShmRefPagesData {
    pub pages_list: [u64; Self::PAGELIST_ENTRIES_PER_PAGE],
    pub next_page_data: u64,
}
impl ShmRefPagesData {
    const PAGELIST_ENTRIES_PER_PAGE: usize = PAGE_SIZE / core::mem::size_of::<u64>() - 1;
}

/// Data structure to maintain the information of OP-TEE shared memory in VTL0 referenced by `shm_ref`.
/// `page_addrs` contains an array of physical page addresses.
/// `page_offset` indicates the page offset of the first page (i.e., `pages[0]`) which should be
/// smaller than `ALIGN`.
#[derive(Clone)]
pub struct ShmInfo<const ALIGN: usize> {
    page_addrs: Box<[PhysPageAddr<ALIGN>]>,
    page_offset: usize,
}

impl<const ALIGN: usize> ShmInfo<ALIGN> {
    pub fn new(
        page_addrs: Box<[PhysPageAddr<ALIGN>]>,
        page_offset: usize,
    ) -> Result<Self, OpteeSmcReturnCode> {
        if page_offset >= ALIGN {
            return Err(OpteeSmcReturnCode::EBadAddr);
        }
        Ok(Self {
            page_addrs,
            page_offset,
        })
    }
}

/// Conversion from `ShmInfo` to `NormalWorldConstPtr` and `NormalWorldMutPtr`.
///
/// OP-TEE shared memory regions are untyped, so we use `u8` as the base type.
impl<const ALIGN: usize> TryFrom<ShmInfo<ALIGN>> for NormalWorldConstPtr<u8, ALIGN> {
    type Error = PhysPointerError;

    fn try_from(shm_info: ShmInfo<ALIGN>) -> Result<Self, Self::Error> {
        NormalWorldConstPtr::new(&shm_info.page_addrs, shm_info.page_offset)
    }
}

impl<const ALIGN: usize> TryFrom<ShmInfo<ALIGN>> for NormalWorldMutPtr<u8, ALIGN> {
    type Error = PhysPointerError;

    fn try_from(shm_info: ShmInfo<ALIGN>) -> Result<Self, Self::Error> {
        NormalWorldMutPtr::new(&shm_info.page_addrs, shm_info.page_offset)
    }
}

/// Maintain the information of OP-TEE shared memory in VTL0 referenced by `shm_ref`.
/// This data structure is for registering shared memory regions before they are
/// used during OP-TEE calls with parameters referencing shared memory.
/// Any normal memory references without this registration will be rejected.
struct ShmRefMap<const ALIGN: usize> {
    inner: spin::mutex::SpinMutex<HashMap<u64, ShmInfo<ALIGN>>>,
}

impl<const ALIGN: usize> ShmRefMap<ALIGN> {
    pub fn new() -> Self {
        Self {
            inner: spin::mutex::SpinMutex::new(HashMap::new()),
        }
    }

    pub fn insert(&self, shm_ref: u64, info: ShmInfo<ALIGN>) -> Result<(), OpteeSmcReturnCode> {
        let mut guard = self.inner.lock();
        if guard.contains_key(&shm_ref) {
            Err(OpteeSmcReturnCode::ENotAvail)
        } else {
            let _ = guard.insert(shm_ref, info);
            Ok(())
        }
    }

    pub fn remove(&self, shm_ref: u64) -> Option<ShmInfo<ALIGN>> {
        let mut guard = self.inner.lock();
        guard.remove(&shm_ref)
    }

    pub fn get(&self, shm_ref: u64) -> Option<ShmInfo<ALIGN>> {
        let guard = self.inner.lock();
        guard.get(&shm_ref).cloned()
    }

    /// This function registers shared memory information that the normal world (VTL0) provides.
    /// Specifically, it walks through a linked list of [`ShmRefPagesData`] structures referenced by
    /// `shm_ref_pages_data_phys_addr` to create a slice of the shared physical page addresses
    /// and registers the slice with `shm_ref` as its identifier. `page_offset` indicates
    /// the page offset of the first page (i.e., `pages_list[0]` of the first [`ShmRefPagesData`]).
    /// `aligned_size` indicates the page-aligned size of the shared memory region to register.
    pub fn register_shm(
        &self,
        shm_ref_pages_data_phys_addr: u64,
        page_offset: u64,
        aligned_size: u64,
        shm_ref: u64,
    ) -> Result<(), OpteeSmcReturnCode> {
        if page_offset >= ALIGN as u64 || aligned_size == 0 {
            return Err(OpteeSmcReturnCode::EBadAddr);
        }
        let num_pages = usize::try_from(aligned_size).unwrap() / ALIGN;
        let mut pages = Vec::with_capacity(num_pages);
        let mut cur_addr = usize::try_from(shm_ref_pages_data_phys_addr).unwrap();
        loop {
            let mut cur_ptr = NormalWorldConstPtr::<ShmRefPagesData, ALIGN>::with_usize(cur_addr)
                .map_err(|_| OpteeSmcReturnCode::EBadAddr)?;
            let pages_data =
                unsafe { cur_ptr.read_at_offset(0) }.map_err(|_| OpteeSmcReturnCode::EBadAddr)?;
            for page in &pages_data.pages_list {
                if *page == 0 || pages.len() == num_pages {
                    break;
                } else {
                    pages.push(
                        PhysPageAddr::new(usize::try_from(*page).unwrap())
                            .ok_or(OpteeSmcReturnCode::EBadAddr)?,
                    );
                }
            }
            if pages_data.next_page_data == 0 || pages.len() == num_pages {
                break;
            } else {
                cur_addr = usize::try_from(pages_data.next_page_data).unwrap();
            }
        }

        self.insert(
            shm_ref,
            ShmInfo::new(
                pages.into_boxed_slice(),
                usize::try_from(page_offset).unwrap(),
            )?,
        )?;
        Ok(())
    }
}

fn shm_ref_map() -> &'static ShmRefMap<PAGE_SIZE> {
    static SHM_REF_MAP: OnceBox<ShmRefMap<PAGE_SIZE>> = OnceBox::new();
    SHM_REF_MAP.get_or_init(|| Box::new(ShmRefMap::new()))
}

/// Get the normal world shared memory information (physical addresses and page offset) from `OpteeMsgParamTmem`.
///
/// TMEM (temporary memory) parameters contain direct physical addresses, unlike RMEM which
/// references pre-registered shared memory regions. For TMEM, we create ShmInfo directly
/// from the physical address without looking up in the shm_ref_map.
fn get_shm_info_from_optee_msg_param_tmem(
    tmem: OpteeMsgParamTmem,
) -> Result<ShmInfo<PAGE_SIZE>, OpteeSmcReturnCode> {
    if tmem.buf_ptr == 0 {
        // NULL buffer - create empty ShmInfo
        return ShmInfo::new(Box::new([]), 0);
    }

    let phys_addr = tmem.buf_ptr;
    let size: usize = tmem.size.truncate();

    // Calculate page-aligned address and offset
    let phys_addr_usize: usize = phys_addr.truncate();
    let page_offset = phys_addr_usize % PAGE_SIZE;
    let aligned_addr = phys_addr - page_offset as u64;

    // Calculate number of pages needed
    let num_pages = (page_offset + size).div_ceil(PAGE_SIZE);

    // Build page address list
    let mut page_addrs = Vec::with_capacity(num_pages);
    for i in 0..num_pages {
        let page_addr = aligned_addr + (i * PAGE_SIZE) as u64;
        page_addrs
            .push(PhysPageAddr::new(page_addr.truncate()).ok_or(OpteeSmcReturnCode::EBadAddr)?);
    }

    ShmInfo::new(page_addrs.into_boxed_slice(), page_offset)
}

/// Get the normal world shared memory information (physical addresses and page offset) from `OpteeMsgParamRmem`.
///
/// `rmem.offs` must be an offset within the shared memory region registered with `rmem.shm_ref` before
/// and `rmem.offs + rmem.size` must not exceed the size of the registered shared memory region.
fn get_shm_info_from_optee_msg_param_rmem(
    rmem: OpteeMsgParamRmem,
) -> Result<ShmInfo<PAGE_SIZE>, OpteeSmcReturnCode> {
    let Some(shm_info) = shm_ref_map().get(rmem.shm_ref) else {
        return Err(OpteeSmcReturnCode::ENotAvail);
    };
    let page_offset = shm_info.page_offset;
    let start = page_offset
        .checked_add(rmem.offs.truncate())
        .ok_or(OpteeSmcReturnCode::EBadAddr)?;
    let end = start
        .checked_add(rmem.size.truncate())
        .ok_or(OpteeSmcReturnCode::EBadAddr)?;
    let start_page_index = start / PAGE_SIZE;
    let end_page_index = end.div_ceil(PAGE_SIZE);
    if start_page_index >= shm_info.page_addrs.len() || end_page_index > shm_info.page_addrs.len() {
        return Err(OpteeSmcReturnCode::EBadAddr);
    }
    let mut page_addrs = Vec::with_capacity(end_page_index - start_page_index);
    page_addrs.extend_from_slice(&shm_info.page_addrs[start_page_index..end_page_index]);
    ShmInfo::new(page_addrs.into_boxed_slice(), start % PAGE_SIZE)
}

/// Read data from the normal world shared memory pages whose physical addresses are given in
/// `shm_info` into `buffer`. The size of `buffer` indicates the number of bytes to read.
fn read_data_from_shm<const ALIGN: usize>(
    shm_info: &ShmInfo<ALIGN>,
    buffer: &mut [u8],
) -> Result<(), OpteeSmcReturnCode> {
    let mut ptr: NormalWorldConstPtr<u8, ALIGN> = shm_info.clone().try_into()?;
    // SAFETY: The data is copied into a buffer owned by LiteBox to avoid TOCTOU issues.
    unsafe {
        ptr.read_slice_at_offset(0, buffer)?;
    }
    Ok(())
}

/// Write data in `buffer` to the normal world shared memory pages whose physical addresses are given
/// in `shm_info`. The size of `buffer` indicates the number of bytes to write.
fn write_data_to_shm<const ALIGN: usize>(
    shm_info: &ShmInfo<ALIGN>,
    buffer: &[u8],
) -> Result<(), OpteeSmcReturnCode> {
    let mut ptr: NormalWorldMutPtr<u8, ALIGN> = shm_info.clone().try_into()?;
    // SAFETY: The data is written from a buffer owned by LiteBox.
    unsafe {
        ptr.write_slice_at_offset(0, buffer)?;
    }
    Ok(())
}
