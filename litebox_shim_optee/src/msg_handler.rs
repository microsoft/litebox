use crate::ptr::{RemoteConstPtr, RemotePtrKind, ValidateAccess};
use alloc::{boxed::Box, vec::Vec};
use hashbrown::HashMap;
use litebox::mm::linux::PAGE_SIZE;
use litebox::platform::RawConstPointer;
use litebox_common_linux::errno::Errno;
use litebox_common_optee::{
    OpteeMessageCommand, OpteeMsgArg, OpteeSecureWorldCapabilities, OpteeSmcArgs, OpteeSmcFunction,
    OpteeSmcResult, OpteeSmcReturn,
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

// TODO: implement a validation mechanism for VTL0 physical addresses (e.g., ensure this physical
// address does not belong to VTL1)
pub struct Novalidation;
impl ValidateAccess for Novalidation {}

pub struct Vtl0PhysAddr;
impl RemotePtrKind for Vtl0PhysAddr {}

/// This function handles `OpteeSmcArgs` passed from the normal world (VTL0) via an OP-TEE SMC call.
/// # Panics
/// Panics if the physical address in `smc` cannot be converted to `usize`.
pub fn handle_optee_smc_args(smc: &mut OpteeSmcArgs) -> Result<OpteeSmcResult<'_>, Errno> {
    let func_id = smc.func_id()?;

    match func_id {
        OpteeSmcFunction::CallWithArg
        | OpteeSmcFunction::CallWithRpcArg
        | OpteeSmcFunction::CallWithRegdArg => {
            let msg_arg_addr = smc.optee_msg_arg_phys_addr()?;
            let msg_arg_addr = usize::try_from(msg_arg_addr).unwrap();
            let remote_ptr =
                RemoteConstPtr::<Novalidation, Vtl0PhysAddr, OpteeMsgArg>::from_usize(msg_arg_addr);
            let msg_arg = unsafe { remote_ptr.read_at_offset(0) }
                .ok_or(Errno::EFAULT)?
                .into_owned();
            // let msg_arg = copy_from_remote_memory::<OpteeMsgArg>(msg_arg_addr)?;
            handle_optee_msg_arg(&msg_arg).map(|()| OpteeSmcResult::Generic {
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
        _ => Err(Errno::EINVAL),
    }
}

pub fn handle_optee_msg_arg(msg_arg: &OpteeMsgArg) -> Result<(), Errno> {
    match msg_arg.cmd {
        OpteeMessageCommand::RegisterShm => {
            if let Ok(tmem) = msg_arg.get_param_tmem(0) {
                shm_ref_map().register_shm(tmem.buf_ptr, tmem.size, tmem.shm_ref)?;
            } else {
                return Err(Errno::EINVAL);
            }
        }
        OpteeMessageCommand::UnregisterShm => {
            if let Ok(tmem) = msg_arg.get_param_tmem(0) {
                shm_ref_map().remove(tmem.shm_ref).ok_or(Errno::ENOENT)?;
            } else {
                return Err(Errno::EINVAL);
            }
        }
        _ => {}
    }

    Ok(())
}

#[derive(Clone)]
struct ShmRefInfo {
    pub pages: Box<[u64]>,
    pub page_offset: u64,
}

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

    pub fn insert(&self, shm_ref: u64, info: ShmRefInfo) -> Result<(), Errno> {
        let mut guard = self.inner.lock();
        if guard.contains_key(&shm_ref) {
            Err(Errno::EEXIST)
        } else {
            let _ = guard.insert(shm_ref, info);
            Ok(())
        }
    }

    pub fn remove(&self, shm_ref: u64) -> Option<ShmRefInfo> {
        let mut guard = self.inner.lock();
        guard.remove(&shm_ref)
    }

    #[expect(unused)]
    pub fn get(&self, shm_ref: u64) -> Option<ShmRefInfo> {
        let guard = self.inner.lock();
        guard.get(&shm_ref).cloned()
    }

    pub fn register_shm(&self, phys_addr: u64, size: u64, shm_ref: u64) -> Result<(), Errno> {
        let aligned_phys_addr = page_align_down(phys_addr);
        let page_offset = phys_addr - aligned_phys_addr;
        let aligned_size = page_align_up(page_offset + size);
        let num_pages = usize::try_from(aligned_size).unwrap() / PAGE_SIZE;
        let mut pages = Vec::with_capacity(num_pages);

        let mut cur_addr = usize::try_from(aligned_phys_addr).unwrap();
        loop {
            let cur_ptr =
                RemoteConstPtr::<Novalidation, Vtl0PhysAddr, ShmRefPagesData>::from_usize(cur_addr);
            let pages_data = unsafe { cur_ptr.read_at_offset(0) }
                .ok_or(Errno::EFAULT)?
                .into_owned();
            for page in &pages_data.pages_list {
                if *page == 0 || pages.len() == num_pages {
                    break;
                } else if !page.is_multiple_of(u64::try_from(PAGE_SIZE).unwrap()) {
                    return Err(Errno::EINVAL);
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
