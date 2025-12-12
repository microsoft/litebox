use crate::ptr::NormalWorldConstPtr;
use alloc::{boxed::Box, vec::Vec};
use hashbrown::HashMap;
use litebox::mm::linux::PAGE_SIZE;
use litebox::platform::RawConstPointer;
use litebox_common_optee::{
    OpteeMessageCommand, OpteeMsgArg, OpteeMsgAttrType, OpteeMsgParamRmem, OpteeMsgParamTmem,
    OpteeSecureWorldCapabilities, OpteeSmcArgs, OpteeSmcFunction, OpteeSmcResult, OpteeSmcReturn,
    UteeEntryFunc, UteeParamOwned,
};
use once_cell::race::OnceBox;

// TODO: Replace these with version and build info
const OPTEE_MSG_REVISION_MAJOR: usize = 2;
const OPTEE_MSG_REVISION_MINOR: usize = 0;
const OPTEE_MSG_BUILD_ID: usize = 0;

// TODO: Replace this with an actual UID
const OPTEE_MSG_UID_0: u32 = 0x384f_b3e0;
const OPTEE_MSG_UID_1: u32 = 0xe7f8_11e3;
const OPTEE_MSG_UID_2: u32 = 0xaf63_0002;
const OPTEE_MSG_UID_3: u32 = 0xa5d5_c51b;

// We do not support notification for now
const MAX_NOTIF_VALUE: usize = 0;
const NUM_RPC_PARMS: usize = 4;

#[inline]
#[cfg(target_pointer_width = "64")]
fn page_align_down(address: u64) -> u64 {
    address & !(PAGE_SIZE as u64 - 1)
}

#[inline]
#[cfg(target_pointer_width = "64")]
fn page_align_up(len: u64) -> u64 {
    len.next_multiple_of(PAGE_SIZE as u64)
}

/// This function handles `OpteeSmcArgs` passed from the normal world (VTL0) via an OP-TEE SMC call.
/// # Panics
/// Panics if the normal world physical address in `smc` cannot be converted to `usize`.
pub fn handle_optee_smc_args(smc: &mut OpteeSmcArgs) -> Result<OpteeSmcResult<'_>, OpteeSmcReturn> {
    let func_id = smc.func_id()?;

    match func_id {
        OpteeSmcFunction::CallWithArg
        | OpteeSmcFunction::CallWithRpcArg
        | OpteeSmcFunction::CallWithRegdArg => {
            let msg_arg_addr = smc.optee_msg_arg_phys_addr()?;
            let msg_arg_addr = usize::try_from(msg_arg_addr).unwrap();
            let ptr = NormalWorldConstPtr::<OpteeMsgArg>::from_usize(msg_arg_addr);
            let msg_arg = unsafe { ptr.read_at_offset(0) }
                .ok_or(OpteeSmcReturn::EBadAddr)?
                .into_owned();
            // let msg_arg = copy_from_remote_memory::<OpteeMsgArg>(msg_arg_addr)?;
            handle_optee_msg_arg(&msg_arg).map(|_| OpteeSmcResult::Generic {
                status: OpteeSmcReturn::Ok,
            })
        }
        OpteeSmcFunction::ExchangeCapabilities => {
            // TODO: update the below when we support more features
            let default_cap = OpteeSecureWorldCapabilities::DYNAMIC_SHM
                | OpteeSecureWorldCapabilities::MEMREF_NULL
                | OpteeSecureWorldCapabilities::RPC_ARG;
            Ok(OpteeSmcResult::ExchangeCapabilities {
                status: OpteeSmcReturn::Ok,
                capabilities: default_cap,
                max_notif_value: MAX_NOTIF_VALUE,
                data: NUM_RPC_PARMS,
            })
        }
        OpteeSmcFunction::DisableShmCache => {
            // We do not support this feature
            Ok(OpteeSmcResult::DisableShmCache {
                status: OpteeSmcReturn::ENotAvail,
                shm_upper32: 0,
                shm_lower32: 0,
            })
        }
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
        _ => Err(OpteeSmcReturn::UnknownFunction),
    }
}

/// This function handles an OP-TEE message contained in `OpteeMsgArg`
pub fn handle_optee_msg_arg(msg_arg: &OpteeMsgArg) -> Result<OpteeMsgArg, OpteeSmcReturn> {
    match msg_arg.cmd {
        OpteeMessageCommand::RegisterShm => {
            if let Ok(tmem) = msg_arg.get_param_tmem(0) {
                shm_ref_map().register_shm(tmem.buf_ptr, tmem.size, tmem.shm_ref)?;
            } else {
                return Err(OpteeSmcReturn::EBadAddr);
            }
        }
        OpteeMessageCommand::UnregisterShm => {
            if let Ok(tmem) = msg_arg.get_param_tmem(0) {
                shm_ref_map()
                    .remove(tmem.shm_ref)
                    .ok_or(OpteeSmcReturn::EBadAddr)?;
            } else {
                return Err(OpteeSmcReturn::EBadCmd);
            }
        }
        OpteeMessageCommand::OpenSession
        | OpteeMessageCommand::InvokeCommand
        | OpteeMessageCommand::CloseSession => return handle_ta_request(msg_arg),
        _ => {
            todo!("Unimplemented OpteeMessageCommand: {:?}", msg_arg.cmd);
        }
    }

    Ok(*msg_arg)
}

/// This function handles a TA request contained in `OpteeMsgArg`
///
/// # Panics
/// Panics if `num_params` cannot be converted to usize.
pub fn handle_ta_request(msg_arg: &OpteeMsgArg) -> Result<OpteeMsgArg, OpteeSmcReturn> {
    let ta_entry_func: UteeEntryFunc = msg_arg.cmd.try_into()?;

    let skip: usize = if ta_entry_func == UteeEntryFunc::OpenSession {
        // TODO: load a TA using its UUID (if not yet loaded)

        2 // first two params are for TA UUID
    } else {
        0
    };
    let num_params: usize = msg_arg.num_params.try_into().unwrap();

    let ta_cmd_id = msg_arg.func;
    let mut ta_params = [const { UteeParamOwned::None }; UteeParamOwned::TEE_NUM_PARAMS];

    // TODO: handle `out_address`
    for (i, param) in msg_arg.params[skip..skip + num_params].iter().enumerate() {
        ta_params[i] = match param.attr_type() {
            OpteeMsgAttrType::None => UteeParamOwned::None,
            OpteeMsgAttrType::ValueInput => {
                let value = param.get_param_value().ok_or(OpteeSmcReturn::EBadCmd)?;
                UteeParamOwned::ValueInput {
                    value_a: value.a,
                    value_b: value.b,
                }
            }
            OpteeMsgAttrType::ValueOutput => UteeParamOwned::ValueOutput { out_address: None },
            OpteeMsgAttrType::ValueInout => {
                let value = param.get_param_value().ok_or(OpteeSmcReturn::EBadCmd)?;
                UteeParamOwned::ValueInout {
                    value_a: value.a,
                    value_b: value.b,
                    out_address: None,
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
                    // TODO: loop to handle scatter-gather list
                    // let ptr = NormalWorldConstPtr::<u8>::from_usize(phys_addr);
                    let slice = alloc::vec![0u8; data_size];
                    UteeParamOwned::MemrefInput { data: slice.into() }
                } else {
                    UteeParamOwned::None
                }
            }
            OpteeMsgAttrType::TmemOutput | OpteeMsgAttrType::RmemOutput => {
                if let (Ok(phys_addrs), buffer_size) = {
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
                    UteeParamOwned::MemrefOutput {
                        buffer_size,
                        out_addresses: Some(phys_addrs),
                    }
                } else {
                    UteeParamOwned::None
                }
            }
            OpteeMsgAttrType::TmemInout | OpteeMsgAttrType::RmemInout => {
                if let (Ok(phys_addrs), buffer_size) = {
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
                    // TODO: loop to handle scatter-gather list
                    // let ptr = NormalWorldConstPtr::<u8>::from_usize(phys_addr);
                    let slice = alloc::vec![0u8; buffer_size];
                    UteeParamOwned::MemrefInout {
                        data: slice.into(),
                        buffer_size,
                        out_addresses: Some(phys_addrs),
                    }
                } else {
                    UteeParamOwned::None
                }
            }
            _ => todo!("handle OpteeMsgParamRmem"),
        }
    }

    Ok(*msg_arg)
}

#[derive(Clone)]
struct ShmRefInfo {
    pub pages: Box<[u64]>,
    pub page_offset: u64,
}

/// Scatter-gather list of OP-TEE shared physical pages in VTL0.
#[derive(Clone, Copy)]
#[repr(C)]
struct ShmRefPagesData {
    pub pages_list: [u64; PAGELIST_ENTRIES_PER_PAGE],
    pub next_page_data: u64,
}
const PAGELIST_ENTRIES_PER_PAGE: usize =
    PAGE_SIZE / core::mem::size_of::<u64>() - core::mem::size_of::<u64>();

/// Maintain the information of OP-TEE shared memory in VTL0 referenced by `shm_ref`.
/// This data structure is for registering shared memory regions before they are
/// used during OP-TEE calls with parameters referencing shared memory.
/// Any normal memory references without this registration will be rejected.
struct ShmRefMap {
    inner: spin::mutex::SpinMutex<HashMap<u64, ShmRefInfo>>,
}

impl ShmRefMap {
    pub fn new() -> Self {
        Self {
            inner: spin::mutex::SpinMutex::new(HashMap::new()),
        }
    }

    pub fn insert(&self, shm_ref: u64, info: ShmRefInfo) -> Result<(), OpteeSmcReturn> {
        let mut guard = self.inner.lock();
        if guard.contains_key(&shm_ref) {
            Err(OpteeSmcReturn::ENotAvail)
        } else {
            let _ = guard.insert(shm_ref, info);
            Ok(())
        }
    }

    pub fn remove(&self, shm_ref: u64) -> Option<ShmRefInfo> {
        let mut guard = self.inner.lock();
        guard.remove(&shm_ref)
    }

    pub fn get(&self, shm_ref: u64) -> Option<ShmRefInfo> {
        let guard = self.inner.lock();
        guard.get(&shm_ref).cloned()
    }

    pub fn register_shm(
        &self,
        phys_addr: u64,
        size: u64,
        shm_ref: u64,
    ) -> Result<(), OpteeSmcReturn> {
        let aligned_phys_addr = page_align_down(phys_addr);
        let page_offset = phys_addr - aligned_phys_addr;
        let aligned_size = page_align_up(page_offset + size);
        let num_pages = usize::try_from(aligned_size).unwrap() / PAGE_SIZE;
        let mut pages = Vec::with_capacity(num_pages);

        let mut cur_addr = usize::try_from(aligned_phys_addr).unwrap();
        loop {
            let cur_ptr = NormalWorldConstPtr::<ShmRefPagesData>::from_usize(cur_addr);
            let pages_data = unsafe { cur_ptr.read_at_offset(0) }
                .ok_or(OpteeSmcReturn::EBadAddr)?
                .into_owned();
            for page in &pages_data.pages_list {
                if *page == 0 || pages.len() == num_pages {
                    break;
                } else if !page.is_multiple_of(u64::try_from(PAGE_SIZE).unwrap()) {
                    return Err(OpteeSmcReturn::EBadAddr);
                } else {
                    pages.push(*page);
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
                page_offset,
            },
        )?;

        Ok(())
    }
}

fn shm_ref_map() -> &'static ShmRefMap {
    static SHM_REF_MAP: OnceBox<ShmRefMap> = OnceBox::new();
    SHM_REF_MAP.get_or_init(|| Box::new(ShmRefMap::new()))
}

/// Get a normal world physical address of OP-TEE shared memory from `OpteeMsgParamTmem`.
/// Note that we use this function for handing TA requests and in that context there is no
/// difference between `OpteeMsgParamTmem` and `OpteeMsgParamRmem`.
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
/// All addresses must be page-aligned except possibly the first one.
/// These addresses are virtually contiguous within the normal world, but not necessarily
/// physically contiguous.
fn get_shm_phys_addrs_from_optee_msg_param_rmem(
    rmem: OpteeMsgParamRmem,
) -> Result<Box<[usize]>, OpteeSmcReturn> {
    let Some(shm_ref_info) = shm_ref_map().get(rmem.shm_ref) else {
        return Err(OpteeSmcReturn::EBadAddr);
    };
    Ok(Box::new([]))
}
