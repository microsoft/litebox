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
use litebox_common_optee::{
    OpteeMessageCommand, OpteeMsgArg, OpteeSecureWorldCapabilities, OpteeSmcArgs, OpteeSmcFunction,
    OpteeSmcResult, OpteeSmcReturn, vmap::PhysPageAddr,
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

/// The result of handling an OP-TEE SMC call along with an extracted OP-TEE message argument to handle.
pub struct OpteeSmcHandled<'a> {
    pub result: OpteeSmcResult<'a>,
    pub msg_to_handle: Option<OpteeMsgArg>,
}

/// This function handles `OpteeSmcArgs` passed from the normal world (VTL0) via an OP-TEE SMC call.
/// It returns an `OpteeSmcResult` representing the result of the SMC call and
/// an optional `OpteeMsgArg` if the SMC call involves with an OP-TEE messagewhich should be handled by
/// `handle_optee_msg_arg` or `handle_ta_request`.
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
/// the message with `handle_ta_request`.
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

/// This function handles a TA request contained in `OpteeMsgArg`
pub fn handle_ta_request(_msg_arg: &OpteeMsgArg) -> Result<OpteeMsgArg, OpteeSmcReturn> {
    todo!()
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
