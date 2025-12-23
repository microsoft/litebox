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
//! physical address containing `OpteeMsgArg` structure (the address is contained in
//! the SMC call arguments). This `OpteeMsgArg` structure may contain references to normal
//! world physical addresses to exchange a large amount of data. Also, like the OP-TEE
//! SMC call, a certain OP-TEE message/command does not involve with any TA (e.g., register
//! shared memory).
use crate::NormalWorldConstPtr;
use alloc::{boxed::Box, vec::Vec};
use hashbrown::HashMap;
use litebox::mm::linux::PAGE_SIZE;
use litebox::platform::vmap::PhysPageAddr;
use litebox_common_optee::{
    OpteeMessageCommand, OpteeMsgArg, OpteeMsgAttrType, OpteeMsgParamRmem, OpteeMsgParamTmem,
    OpteeMsgParamValue, OpteeSecureWorldCapabilities, OpteeSmcArgs, OpteeSmcFunction,
    OpteeSmcResult, OpteeSmcReturn, TeeParamType, TeeUuid, UteeEntryFunc, UteeParamOwned,
    UteeParams,
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
fn page_align_down_u64(address: u64) -> u64 {
    address & !(PAGE_SIZE as u64 - 1)
}

#[inline]
fn page_align_down(address: usize) -> usize {
    address & !(PAGE_SIZE - 1)
}

#[inline]
fn page_align_up_u64(len: u64) -> u64 {
    len.next_multiple_of(PAGE_SIZE as u64)
}

/// The result of handling an OP-TEE SMC call along with an extracted OP-TEE message argument to handle.
pub struct OpteeSmcHandled<'a> {
    pub result: OpteeSmcResult<'a>,
    pub msg_to_handle: Option<OpteeMsgArg>,
}

/// This function handles `OpteeSmcArgs` passed from the normal world (VTL0) via an OP-TEE SMC call.
/// It returns an `OpteeSmcResult` representing the result of the SMC call and
/// an optional `OpteeMsgArg` if the SMC call involves with an OP-TEE message which should be handled by
/// `handle_optee_msg_arg` or `decode_ta_request`.
///
/// # Panics
///
/// Panics if the normal world physical address in `smc` cannot be converted to `usize`.
pub fn handle_optee_smc_args(
    smc: &mut OpteeSmcArgs,
) -> Result<OpteeSmcHandled<'_>, OpteeSmcReturn> {
    let func_id = smc.func_id()?;
    match func_id {
        OpteeSmcFunction::CallWithArg
        | OpteeSmcFunction::CallWithRpcArg
        | OpteeSmcFunction::CallWithRegdArg => {
            let msg_arg_addr = smc.optee_msg_arg_phys_addr()?;
            let msg_arg_addr = usize::try_from(msg_arg_addr).unwrap();
            let mut ptr = NormalWorldConstPtr::<OpteeMsgArg, PAGE_SIZE>::with_usize(msg_arg_addr)
                .map_err(|_| OpteeSmcReturn::EBadAddr)?;
            let msg_arg = unsafe { ptr.read_at_offset(0) }.map_err(|_| OpteeSmcReturn::EBadAddr)?;
            Ok(OpteeSmcHandled {
                result: OpteeSmcResult::Generic {
                    status: OpteeSmcReturn::Ok,
                },
                msg_to_handle: Some(*msg_arg),
            })
        }
        OpteeSmcFunction::ExchangeCapabilities => {
            // TODO: update the below when we support more features
            let default_cap = OpteeSecureWorldCapabilities::DYNAMIC_SHM
                | OpteeSecureWorldCapabilities::MEMREF_NULL
                | OpteeSecureWorldCapabilities::RPC_ARG;
            Ok(OpteeSmcHandled {
                result: OpteeSmcResult::ExchangeCapabilities {
                    status: OpteeSmcReturn::Ok,
                    capabilities: default_cap,
                    max_notif_value: MAX_NOTIF_VALUE,
                    data: NUM_RPC_PARMS,
                },
                msg_to_handle: None,
            })
        }
        OpteeSmcFunction::DisableShmCache => {
            // Currently, we do not support this feature.
            Ok(OpteeSmcHandled {
                result: OpteeSmcResult::DisableShmCache {
                    status: OpteeSmcReturn::ENotAvail,
                    shm_upper32: 0,
                    shm_lower32: 0,
                },
                msg_to_handle: None,
            })
        }
        OpteeSmcFunction::GetOsUuid => Ok(OpteeSmcHandled {
            result: OpteeSmcResult::Uuid {
                data: &[
                    OPTEE_MSG_OS_OPTEE_UUID_0,
                    OPTEE_MSG_OS_OPTEE_UUID_1,
                    OPTEE_MSG_OS_OPTEE_UUID_2,
                    OPTEE_MSG_OS_OPTEE_UUID_3,
                ],
            },
            msg_to_handle: None,
        }),
        OpteeSmcFunction::CallsUid => Ok(OpteeSmcHandled {
            result: OpteeSmcResult::Uuid {
                data: &[
                    OPTEE_MSG_UID_0,
                    OPTEE_MSG_UID_1,
                    OPTEE_MSG_UID_2,
                    OPTEE_MSG_UID_3,
                ],
            },
            msg_to_handle: None,
        }),
        OpteeSmcFunction::GetOsRevision => Ok(OpteeSmcHandled {
            result: OpteeSmcResult::OsRevision {
                major: OPTEE_MSG_REVISION_MAJOR,
                minor: OPTEE_MSG_REVISION_MINOR,
                build_id: OPTEE_MSG_BUILD_ID,
            },
            msg_to_handle: None,
        }),
        OpteeSmcFunction::CallsRevision => Ok(OpteeSmcHandled {
            result: OpteeSmcResult::Revision {
                major: OPTEE_MSG_REVISION_MAJOR,
                minor: OPTEE_MSG_REVISION_MINOR,
            },
            msg_to_handle: None,
        }),
        _ => Err(OpteeSmcReturn::UnknownFunction),
    }
}

/// This function handles an OP-TEE message contained in `OpteeMsgArg`.
/// Currently, it only handles shared memory registration and unregistration.
/// If an OP-TEE message involves with a TA request, it simply returns
/// `Err(OpteeSmcReturn::Ok)` while expecting that the caller will handle
/// the message with `decode_ta_request`.
pub fn handle_optee_msg_arg(msg_arg: &OpteeMsgArg) -> Result<(), OpteeSmcReturn> {
    msg_arg.validate()?;
    match msg_arg.cmd {
        OpteeMessageCommand::RegisterShm => {
            let tmem = msg_arg.get_param_tmem(0)?;
            if tmem.buf_ptr == 0 || tmem.size == 0 || tmem.shm_ref == 0 {
                return Err(OpteeSmcReturn::EBadAddr);
            }
            // `tmem.buf_ptr` encodes two different information:
            // - The physical page address of the first `ShmRefPagesData`
            // - The page offset of the first shared memory page (`pages_list[0]`)
            let shm_ref_pages_data_phys_addr = page_align_down_u64(tmem.buf_ptr);
            let page_offset = tmem.buf_ptr - shm_ref_pages_data_phys_addr;
            let aligned_size = page_align_up_u64(page_offset + tmem.size);
            shm_ref_map().register_shm(
                shm_ref_pages_data_phys_addr,
                page_offset,
                aligned_size,
                tmem.shm_ref,
            )?;
        }
        OpteeMessageCommand::UnregisterShm => {
            let tmem = msg_arg.get_param_tmem(0)?;
            if tmem.shm_ref == 0 {
                return Err(OpteeSmcReturn::EBadAddr);
            }
            shm_ref_map()
                .remove(tmem.shm_ref)
                .ok_or(OpteeSmcReturn::EBadAddr)?;
        }
        OpteeMessageCommand::OpenSession
        | OpteeMessageCommand::InvokeCommand
        | OpteeMessageCommand::CloseSession => return Err(OpteeSmcReturn::Ok),
        _ => {
            todo!("Unimplemented OpteeMessageCommand: {:?}", msg_arg.cmd);
        }
    }
    Ok(())
}

/// TA request information extracted from an OP-TEE message.
/// In addition to standard TA information (i.e., TA UUID, session ID, command ID,
/// and parameters), it contains shared memory addresses (`out_phys_addrs`) to
/// write back output data to the normal world once the TA execution is done.
pub struct TaRequestInfo {
    pub uuid: Option<TeeUuid>,
    pub session: u32,
    pub entry_func: UteeEntryFunc,
    pub cmd_id: u32,
    pub params: [UteeParamOwned; UteeParamOwned::TEE_NUM_PARAMS],
    pub out_phys_addrs: [Option<Box<[usize]>>; UteeParamOwned::TEE_NUM_PARAMS],
}

/// This function decodes a TA request contained in `OpteeMsgArg`.
/// Currently, this function copies the entire parameter data from the normal world
/// shared memory into LiteBox's memory to create `UteeParamOwned` structures.
/// Clearly, this approach is inefficient and we need to revise it to avoid unnecessary
/// data copies (while maintaining the security).
/// # Panics
/// Panics if any conversion from `u64` to `usize` fails. OP-TEE shim doesn't support a 32-bit environment.
pub fn decode_ta_request(msg_arg: &OpteeMsgArg) -> Result<TaRequestInfo, OpteeSmcReturn> {
    let ta_entry_func: UteeEntryFunc = msg_arg.cmd.try_into()?;
    let (ta_uuid, skip): (Option<TeeUuid>, usize) = if ta_entry_func == UteeEntryFunc::OpenSession {
        // If it is an OpenSession request, extract the TA UUID from the first two parameters
        let mut data = [0u32; 4];
        data[0] = (msg_arg.get_param_value(0)?.a).truncate();
        data[1] = (msg_arg.get_param_value(0)?.b).truncate();
        data[2] = (msg_arg.get_param_value(1)?.a).truncate();
        data[3] = (msg_arg.get_param_value(1)?.b).truncate();
        (Some(TeeUuid::new_from_u32s(data)), 2)
    } else {
        (None, 0)
    };

    let mut ta_req_info = TaRequestInfo {
        uuid: ta_uuid,
        session: msg_arg.session,
        entry_func: ta_entry_func,
        cmd_id: msg_arg.func,
        params: [const { UteeParamOwned::None }; UteeParamOwned::TEE_NUM_PARAMS],
        out_phys_addrs: [const { None }; UteeParamOwned::TEE_NUM_PARAMS],
    };

    let num_params = msg_arg.num_params as usize;
    for (i, param) in msg_arg
        .params
        .iter()
        .take(num_params)
        .skip(skip)
        .enumerate()
    {
        ta_req_info.params[i] = match param.attr_type() {
            OpteeMsgAttrType::None => UteeParamOwned::None,
            OpteeMsgAttrType::ValueInput => {
                let value = param.get_param_value().ok_or(OpteeSmcReturn::EBadCmd)?;
                UteeParamOwned::ValueInput {
                    value_a: value.a,
                    value_b: value.b,
                }
            }
            OpteeMsgAttrType::ValueOutput => UteeParamOwned::ValueOutput {},
            OpteeMsgAttrType::ValueInout => {
                let value = param.get_param_value().ok_or(OpteeSmcReturn::EBadCmd)?;
                UteeParamOwned::ValueInout {
                    value_a: value.a,
                    value_b: value.b,
                }
            }
            OpteeMsgAttrType::TmemInput | OpteeMsgAttrType::RmemInput => {
                if let (Ok(phys_addrs), data_size) = {
                    match param.attr_type() {
                        OpteeMsgAttrType::TmemInput => {
                            let tmem = param.get_param_tmem().ok_or(OpteeSmcReturn::EBadCmd)?;
                            (
                                get_shm_phys_addrs_from_optee_msg_param_tmem(tmem),
                                usize::try_from(tmem.size).unwrap(),
                            )
                        }
                        OpteeMsgAttrType::RmemInput => {
                            let rmem = param.get_param_rmem().ok_or(OpteeSmcReturn::EBadCmd)?;
                            (
                                get_shm_phys_addrs_from_optee_msg_param_rmem(rmem),
                                usize::try_from(rmem.size).unwrap(),
                            )
                        }
                        _ => unreachable!(),
                    }
                } {
                    let mut data = alloc::vec![0u8; data_size];
                    read_data_from_shm_phys_addrs(&phys_addrs, &mut data)?;
                    UteeParamOwned::MemrefInput { data: data.into() }
                } else {
                    UteeParamOwned::None
                }
            }
            OpteeMsgAttrType::TmemOutput | OpteeMsgAttrType::RmemOutput => {
                if let (Ok(phys_addrs), buffer_size) = {
                    match param.attr_type() {
                        OpteeMsgAttrType::TmemOutput => {
                            let tmem = param.get_param_tmem().ok_or(OpteeSmcReturn::EBadCmd)?;
                            (
                                get_shm_phys_addrs_from_optee_msg_param_tmem(tmem),
                                usize::try_from(tmem.size).unwrap(),
                            )
                        }
                        OpteeMsgAttrType::RmemOutput => {
                            let rmem = param.get_param_rmem().ok_or(OpteeSmcReturn::EBadCmd)?;
                            (
                                get_shm_phys_addrs_from_optee_msg_param_rmem(rmem),
                                usize::try_from(rmem.size).unwrap(),
                            )
                        }
                        _ => unreachable!(),
                    }
                } {
                    ta_req_info.out_phys_addrs[i] = Some(phys_addrs);
                    UteeParamOwned::MemrefOutput { buffer_size }
                } else {
                    UteeParamOwned::None
                }
            }
            OpteeMsgAttrType::TmemInout | OpteeMsgAttrType::RmemInout => {
                if let (Ok(phys_addrs), buffer_size) = {
                    match param.attr_type() {
                        OpteeMsgAttrType::TmemInout => {
                            let tmem = param.get_param_tmem().ok_or(OpteeSmcReturn::EBadCmd)?;
                            (
                                get_shm_phys_addrs_from_optee_msg_param_tmem(tmem),
                                usize::try_from(tmem.size).unwrap(),
                            )
                        }
                        OpteeMsgAttrType::RmemInout => {
                            let rmem = param.get_param_rmem().ok_or(OpteeSmcReturn::EBadCmd)?;
                            (
                                get_shm_phys_addrs_from_optee_msg_param_rmem(rmem),
                                usize::try_from(rmem.size).unwrap(),
                            )
                        }
                        _ => unreachable!(),
                    }
                } {
                    let mut buffer = alloc::vec![0u8; buffer_size];
                    read_data_from_shm_phys_addrs(&phys_addrs, &mut buffer)?;
                    ta_req_info.out_phys_addrs[i] = Some(phys_addrs);
                    UteeParamOwned::MemrefInout {
                        data: buffer.into(),
                        buffer_size,
                    }
                } else {
                    UteeParamOwned::None
                }
            }
            _ => return Err(OpteeSmcReturn::EBadCmd),
        };
    }

    Ok(ta_req_info)
}

/// This function prepares for returning from OP-TEE secure world to the normal world.
/// In particular, it writes back TA execution outputs associated with shared memory references and
/// updates the `OpteeMsgArg` structure to return value-based outputs.
/// `ta_params` is a reference to `UteeParams` structure that stores TA's output within its memory.
/// `ta_req_info` refers to the decoded TA request information including the normal world
/// shared memory addresses to write back output data.
pub fn prepare_for_return_to_normal_world(
    ta_params: &UteeParams,
    ta_req_info: &TaRequestInfo,
    msg_arg: &mut OpteeMsgArg,
) -> Result<(), OpteeSmcReturn> {
    for index in 0..UteeParams::TEE_NUM_PARAMS {
        let param_type = ta_params
            .get_type(index)
            .map_err(|_| OpteeSmcReturn::EBadAddr)?;
        match param_type {
            TeeParamType::ValueOutput | TeeParamType::ValueInout => {
                if let Ok(Some((value_a, value_b))) = ta_params.get_values(index) {
                    msg_arg.set_param_value(
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
                    let slice = unsafe {
                        &*core::ptr::slice_from_raw_parts(
                            addr as *const u8,
                            usize::try_from(len).unwrap_or(0),
                        )
                    };
                    if slice.is_empty() {
                        continue;
                    }
                    if let Some(out_addrs) = &ta_req_info.out_phys_addrs[index] {
                        write_data_to_shm_phys_addrs(out_addrs, slice)?;
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
    const PAGELIST_ENTRIES_PER_PAGE: usize =
        PAGE_SIZE / core::mem::size_of::<u64>() - core::mem::size_of::<u64>();
}

/// Data structure to maintain the information of OP-TEE shared memory in VTL0 referenced by `shm_ref`.
/// `pages` contains an array of physical page addresses.
/// `page_offset` indicates the page offset of the first page (i.e., `pages[0]`) which should be
/// smaller than `ALIGN`.
#[expect(unused)]
#[derive(Clone)]
struct ShmRefInfo<const ALIGN: usize> {
    pub pages: Box<[PhysPageAddr<ALIGN>]>,
    pub page_offset: usize,
}

/// Maintain the information of OP-TEE shared memory in VTL0 referenced by `shm_ref`.
/// This data structure is for registering shared memory regions before they are
/// used during OP-TEE calls with parameters referencing shared memory.
/// Any normal memory references without this registration will be rejected.
struct ShmRefMap<const ALIGN: usize> {
    inner: spin::mutex::SpinMutex<HashMap<u64, ShmRefInfo<ALIGN>>>,
}

impl<const ALIGN: usize> ShmRefMap<ALIGN> {
    pub fn new() -> Self {
        Self {
            inner: spin::mutex::SpinMutex::new(HashMap::new()),
        }
    }

    pub fn insert(&self, shm_ref: u64, info: ShmRefInfo<ALIGN>) -> Result<(), OpteeSmcReturn> {
        let mut guard = self.inner.lock();
        if guard.contains_key(&shm_ref) {
            Err(OpteeSmcReturn::ENotAvail)
        } else {
            let _ = guard.insert(shm_ref, info);
            Ok(())
        }
    }

    pub fn remove(&self, shm_ref: u64) -> Option<ShmRefInfo<ALIGN>> {
        let mut guard = self.inner.lock();
        guard.remove(&shm_ref)
    }

    #[expect(unused)]
    pub fn get(&self, shm_ref: u64) -> Option<ShmRefInfo<ALIGN>> {
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
    ) -> Result<(), OpteeSmcReturn> {
        if page_offset >= ALIGN as u64 || aligned_size == 0 {
            return Err(OpteeSmcReturn::EBadAddr);
        }
        let num_pages = usize::try_from(aligned_size).unwrap() / ALIGN;
        let mut pages = Vec::with_capacity(num_pages);
        let mut cur_addr = usize::try_from(shm_ref_pages_data_phys_addr).unwrap();
        loop {
            let mut cur_ptr = NormalWorldConstPtr::<ShmRefPagesData, ALIGN>::with_usize(cur_addr)
                .map_err(|_| OpteeSmcReturn::EBadAddr)?;
            let pages_data =
                unsafe { cur_ptr.read_at_offset(0) }.map_err(|_| OpteeSmcReturn::EBadAddr)?;
            for page in &pages_data.pages_list {
                if *page == 0 || pages.len() == num_pages {
                    break;
                } else {
                    pages.push(
                        PhysPageAddr::new(usize::try_from(*page).unwrap())
                            .ok_or(OpteeSmcReturn::EBadAddr)?,
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
            ShmRefInfo {
                pages: pages.into_boxed_slice(),
                page_offset: usize::try_from(page_offset).unwrap(),
            },
        )?;
        Ok(())
    }
}

fn shm_ref_map() -> &'static ShmRefMap<PAGE_SIZE> {
    static SHM_REF_MAP: OnceBox<ShmRefMap<PAGE_SIZE>> = OnceBox::new();
    SHM_REF_MAP.get_or_init(|| Box::new(ShmRefMap::new()))
}

/// Get the normal world physical addresses of OP-TEE shared memory from `OpteeMsgParamTmem`.
/// Note that we use this function for handing TA requests and in this context
/// `OpteeMsgParamTmem` and `OpteeMsgParamRmem` are equivalent because every shared memory
/// reference accessible by TAs must be registered in advance.
/// `OpteeMsgParamTmem` is matter for the registration of shared memory regions.
fn get_shm_phys_addrs_from_optee_msg_param_tmem(
    tmem: OpteeMsgParamTmem,
) -> Result<Box<[usize]>, OpteeSmcReturn> {
    let rmem = OpteeMsgParamRmem {
        offs: tmem.buf_ptr,
        size: tmem.size,
        shm_ref: tmem.shm_ref,
    };
    get_shm_phys_addrs_from_optee_msg_param_rmem(rmem)
}

/// Get a list of the normal world physical addresses of OP-TEE shared memory from `OpteeMsgParamRmem`.
/// `rmem.offs` must be an offset within the shared memory region registered with `rmem.shm_ref` before
/// and `rmem.offs + rmem.size` must not exceed the size of the registered shared memory region.
/// All addresses this function returns are page-aligned except the first one. These addresses are
/// virtually contiguous within the normal world, but not necessarily physically contiguous.
fn get_shm_phys_addrs_from_optee_msg_param_rmem(
    rmem: OpteeMsgParamRmem,
) -> Result<Box<[usize]>, OpteeSmcReturn> {
    let Some(shm_ref_info) = shm_ref_map().get(rmem.shm_ref) else {
        return Err(OpteeSmcReturn::ENotAvail);
    };
    let start = shm_ref_info
        .page_offset
        .checked_add(rmem.offs)
        .ok_or(OpteeSmcReturn::EBadAddr)?;
    let end = start
        .checked_add(rmem.size)
        .ok_or(OpteeSmcReturn::EBadAddr)?;
    let start_page_index = usize::try_from(page_align_down_u64(start)).unwrap() / PAGE_SIZE;
    let end_page_index = usize::try_from(page_align_up_u64(end)).unwrap() / PAGE_SIZE;
    if start_page_index >= shm_ref_info.pages.len() || end_page_index > shm_ref_info.pages.len() {
        return Err(OpteeSmcReturn::EBadAddr);
    }
    let mut pages = Vec::with_capacity(end_page_index - start_page_index);
    let page_offset = start - page_align_down_u64(start);
    pages[0] = usize::try_from(shm_ref_info.pages[start_page_index] + page_offset).unwrap();
    for (i, page) in shm_ref_info
        .pages
        .iter()
        .take(end_page_index)
        .skip(start_page_index)
        .enumerate()
    {
        pages[i] = usize::try_from(*page).unwrap();
    }
    Ok(pages.into_boxed_slice())
}

/// Read data from the normal world shared memory pages whose physical addresses are given in
/// `phys_addrs` into `buffer`. The size of `buffer` indicates how many bytes to read.
/// All physical addresses in `phys_addrs` are page-aligned except the first one.
fn read_data_from_shm_phys_addrs(
    phys_addrs: &[usize],
    buffer: &mut [u8],
) -> Result<(), OpteeSmcReturn> {
    let mut array: Vec<usize> = Vec::with_capacity(phys_addrs.len());
    array.push(page_align_down(phys_addrs[0]));
    array.extend_from_slice(&phys_addrs[1..]);
    let page_array = PhysPageArray::<PAGE_SIZE>::try_from_slice(array.as_slice())?;
    let mut ptr = NormalWorldConstPtr::<u8, PAGE_SIZE>::try_from_page_array(
        page_array,
        phys_addrs[0] - array[0],
    )?;
    unsafe {
        ptr.read_slice_at_offset(0, buffer)?;
    }
    Ok(())
}

/// Write data in `buffer` to the normal world shared memory pages whose physical addresses
/// are given in `phys_addrs`. The size of `buffer` indicates how many bytes to write.
/// All physical addresses in `phys_addrs` are page-aligned except the first one.
fn write_data_to_shm_phys_addrs(phys_addrs: &[usize], buffer: &[u8]) -> Result<(), OpteeSmcReturn> {
    let mut array: Vec<usize> = Vec::with_capacity(phys_addrs.len());
    array.push(page_align_down(phys_addrs[0]));
    array.extend_from_slice(&phys_addrs[1..]);
    let page_array = PhysPageArray::<PAGE_SIZE>::try_from_slice(array.as_slice())?;
    let mut ptr = NormalWorldMutPtr::<u8, PAGE_SIZE>::try_from_page_array(
        page_array,
        phys_addrs[0] - array[0],
    )
    .map_err(|_| OpteeSmcReturn::EBadAddr)?;
    unsafe {
        ptr.write_slice_at_offset(0, buffer)?;
    }
    Ok(())
}

impl From<PhysPointerError> for OpteeSmcReturn {
    fn from(err: PhysPointerError) -> Self {
        match err {
            PhysPointerError::AlreadyMapped(_) => OpteeSmcReturn::EBusy,
            PhysPointerError::NoMappingInfo => OpteeSmcReturn::ENomem,
            _ => OpteeSmcReturn::EBadAddr,
        }
    }
}
