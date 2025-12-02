//! VSM OP-TEE SMC functions
//!
extern crate alloc;

use alloc::{boxed::Box, vec::Vec};
use hashbrown::HashMap;
use litebox::mm::linux::PAGE_SIZE;
use litebox_common_linux::errno::Errno;
use num_enum::TryFromPrimitive;
use once_cell::race::OnceBox;
use x86_64::{PhysAddr, align_down, align_up};

/// Opaque value parameter
/// Value parameters are passed unchecked between normal and secure world
#[derive(Clone, Copy)]
#[repr(C)]
struct OpteeMsgParamValue {
    a: u64,
    b: u64,
    c: u64,
}

#[derive(Clone, Copy)]
#[repr(C)]
struct OpteeMsgParam {
    attr: u64,
    value: OpteeMsgParamValue,
}

/// `OpteeMsgArg` represents the message argument structure exchanged between
/// normal world and secure world (i.e., OP-TEE) for various OP-TEE operations including
/// TA command invocation and shared memory management.
#[derive(Clone, Copy)]
#[repr(C)]
struct OpteeMsgArg {
    cmd: u32,
    func: u32,
    session: u32,
    cancel_id: u32,
    pad: u32,
    ret: u32,
    ret_origin: u32,
    num_params: u32,
    params: [OpteeMsgParam; Self::MAX_NUM_PARAMS],
}

impl OpteeMsgArg {
    // if `cmd` is `OpenSession`, the first two params represent TA UUID and they are not passed to TA
    const MAX_NUM_PARAMS: usize = 6;
}

/// OP-TEE SMC call arguments. OP-TEE assumes that the underlying architecture is Arm with TrustZone.
/// This is why it uses Secure Monitor Call (SMC) calling convention (SMCCC).
/// We translate SMCCC into VTL switch convention. Specifically, we reserve a page in normal world
/// memory to exchange OP-TEE SMC call arguments and results (up to nine 64-bit values).
/// The meaning of args[0-8] varies depending on the OP-TEE SMC function ID and `OpteeSmcResult`.
#[repr(align(4096))]
#[derive(Clone, Copy)]
#[repr(C)]
struct OpteeSmcArgs {
    args: [usize; Self::NUM_OPTEE_SMC_ARGS],
}

impl OpteeSmcArgs {
    const NUM_OPTEE_SMC_ARGS: usize = 9;

    /// Get the function ID of an OP-TEE SMC call.
    fn func_id(&self) -> Result<OpteeSmcFunction, Errno> {
        OpteeSmcFunction::try_from(self.args[0] & OpteeSmcFunction::MASK).map_err(|_| Errno::EINVAL)
    }

    /// Get the physical address of `OpteeMsgArg` from normal world memory using OP-TEE SMC call arguments.
    /// It uses `args[1]` and `args[2]` to form a 64-bit physical address.
    /// Note: In many places, OP-TEE only uses the lower 32 bit portion of a 64 bit variable to avoid
    /// potential overflows.
    fn optee_msg_arg_phys_addr(&self) -> Result<PhysAddr, Errno> {
        let addr = ((self.args[1] as u64) << 32) | (self.args[2] as u64);
        PhysAddr::try_new(addr).map_err(|_| Errno::EINVAL)
    }

    /// Get the physical address of `OpteeMsgArg` from normal world's "registered" memory using
    /// OP-TEE SMC call arguments.
    /// It uses `args[1]` and `args[2]` to form a 64-bit base physical address and
    /// adds `args[3]` as an offset.
    fn optee_msg_arg_phys_addr_from_cookie(&self) -> Result<PhysAddr, Errno> {
        let addr = ((self.args[1] as u64) << 32) | (self.args[2] as u64);
        addr.checked_add(u64::try_from(self.args[3]).unwrap())
            .ok_or(Errno::EINVAL)?;
        PhysAddr::try_new(addr).map_err(|_| Errno::EINVAL)
    }

    /// Get `OpteeMsgArg` and its physical address from normal world's memory using OP-TEE SMC call arguments.
    #[expect(dead_code)]
    fn optee_msg_arg(&self) -> Result<(OpteeMsgArg, usize), Errno> {
        let msg_arg_addr = match self.func_id() {
            Ok(OpteeSmcFunction::CallWithArg | OpteeSmcFunction::CallWithRpcArg) => {
                self.optee_msg_arg_phys_addr()
            }
            Ok(OpteeSmcFunction::CallWithRegdArg) => self.optee_msg_arg_phys_addr_from_cookie(),
            _ => Err(Errno::EINVAL),
        }?;

        // TODO: copy actual data from normal world's memory using its physical address. That is,
        // we need a public API to access normal world's memory.
        Ok((
            OpteeMsgArg {
                cmd: 0,
                func: 0,
                session: 0,
                cancel_id: 0,
                pad: 0,
                ret: 0,
                ret_origin: 0,
                num_params: 0,
                params: [OpteeMsgParam {
                    attr: 0,
                    value: OpteeMsgParamValue { a: 0, b: 0, c: 0 },
                }; OpteeMsgArg::MAX_NUM_PARAMS],
            },
            usize::try_from(msg_arg_addr.as_u64()).unwrap(),
        ))
        // copy_from_vtl0_phys is a private or crate-internal API.
        // if let Some(msg_arg) =
        //     unsafe { crate::platform_low().copy_from_vtl0_phys::<OpteeMsgArg>(msg_arg_addr) }
        // {
        //     Ok((*msg_arg, usize::try_from(msg_arg_addr.as_u64()).unwrap()))
        // } else {
        //     Err(Errno::EINVAL)
        // }
    }

    /// Set `OpteeMsgArg` into normal world's memory using OP-TEE SMC call arguments to return the result.
    fn set_optee_msg_arg(&self, _msg_arg: &OpteeMsgArg) -> Result<(), Errno> {
        let _msg_arg_addr = match self.func_id() {
            Ok(OpteeSmcFunction::CallWithArg | OpteeSmcFunction::CallWithRpcArg) => {
                self.optee_msg_arg_phys_addr()
            }
            Ok(OpteeSmcFunction::CallWithRegdArg) => self.optee_msg_arg_phys_addr_from_cookie(),
            _ => Err(Errno::EINVAL),
        }?;

        // TODO: write data to normal world's memory using its physical address.
        Ok(())
        // if unsafe { crate::platform_low().copy_to_vtl0_phys::<OpteeMsgArg>(msg_arg_addr, msg_arg) }
        // {
        //     Ok(())
        // } else {
        //     Err(Errno::EINVAL)
        // }
    }

    /// Set the result of an OP-TEE SMC call. This function overwrites normal world's memory containing
    /// `OpteeSmcArgs` and possibly `OpteeMsgArg`.
    fn set_result(&mut self, result: &OpteeSmcResult, msg_arg: Option<&OpteeMsgArg>) {
        match result {
            OpteeSmcResult::Generic { status } => {
                self.args[0] = *status as usize;
                if let Some(msg_arg) = msg_arg {
                    let _ = self.set_optee_msg_arg(msg_arg);
                }
            }
            OpteeSmcResult::ExchangeCapabilities {
                status,
                capabilities,
                max_notif_value,
                data,
            } => {
                self.args[0] = *status as usize;
                self.args[1] = capabilities.bits();
                self.args[2] = *max_notif_value;
                self.args[3] = *data;
            }
            OpteeSmcResult::DisableShmCache {
                status,
                shm_upper32,
                shm_lower32,
            } => {
                self.args[0] = *status as usize;
                self.args[1] = *shm_upper32;
                self.args[2] = *shm_lower32;
            }
            OpteeSmcResult::Uuid { data } => {
                self.args[0] = usize::try_from(data[0]).unwrap();
                self.args[1] = usize::try_from(data[1]).unwrap();
                self.args[2] = usize::try_from(data[2]).unwrap();
                self.args[3] = usize::try_from(data[3]).unwrap();
            }
            OpteeSmcResult::Revision { major, minor } => {
                self.args[0] = *major;
                self.args[1] = *minor;
            }
            OpteeSmcResult::OsRevision {
                major,
                minor,
                build_id,
            } => {
                self.args[0] = *major;
                self.args[1] = *minor;
                self.args[2] = *build_id;
            }
        }
    }
}

const OPTEE_SMC_FUNCID_GET_OS_REVISION: usize = 0x1;
const OPTEE_SMC_FUNCID_CALL_WITH_ARG: usize = 0x4;
const OPTEE_SMC_FUNCID_EXCHANGE_CAPABILITIES: usize = 0x9;
const OPTEE_SMC_FUNCID_DISABLE_SHM_CACHE: usize = 0xa;
const OPTEE_SMC_FUNCID_CALL_WITH_RPC_ARG: usize = 0x12;
const OPTEE_SMC_FUNCID_CALL_WITH_REGD_ARG: usize = 0x13;

const OPTEE_SMC_FUNCID_CALLS_UID: usize = 0xff01;
const OPTEE_SMC_FUNCID_CALLS_REVISION: usize = 0xff03;

#[derive(PartialEq, TryFromPrimitive)]
#[repr(usize)]
enum OpteeSmcFunction {
    GetOsRevision = OPTEE_SMC_FUNCID_GET_OS_REVISION,
    CallWithArg = OPTEE_SMC_FUNCID_CALL_WITH_ARG,
    ExchangeCapabilities = OPTEE_SMC_FUNCID_EXCHANGE_CAPABILITIES,
    DisableShmCache = OPTEE_SMC_FUNCID_DISABLE_SHM_CACHE,
    CallWithRpcArg = OPTEE_SMC_FUNCID_CALL_WITH_RPC_ARG,
    CallWithRegdArg = OPTEE_SMC_FUNCID_CALL_WITH_REGD_ARG,
    CallsUid = OPTEE_SMC_FUNCID_CALLS_UID,
    CallsRevision = OPTEE_SMC_FUNCID_CALLS_REVISION,
}

impl OpteeSmcFunction {
    const MASK: usize = 0xffff;
}

#[allow(dead_code)]
enum OpteeSmcResult {
    Generic {
        status: OpteeSmcReturn,
    },
    ExchangeCapabilities {
        status: OpteeSmcReturn,
        capabilities: OpteeSecureWorldCapabilities,
        max_notif_value: usize,
        data: usize,
    },
    DisableShmCache {
        status: OpteeSmcReturn,
        shm_upper32: usize,
        shm_lower32: usize,
    },
    Uuid {
        data: [u32; 4],
    },
    Revision {
        major: usize,
        minor: usize,
    },
    OsRevision {
        major: usize,
        minor: usize,
        build_id: usize,
    },
}

bitflags::bitflags! {
    #[derive(PartialEq, Clone, Copy)]
    #[non_exhaustive]
    struct OpteeSecureWorldCapabilities: usize {
        const HAVE_RESERVED_SHM = 1 << 0;
        const UNREGISTERED_SHM = 1 << 1;
        const DYNAMIC_SHM = 1 << 2;
        const MEMREF_NULL = 1 << 4;
        const RPC_ARG = 1 << 6;
        const _ = !0;
    }
}

const NUM_RPC_PARAMS: usize = 4;

// dummy values for OP-TEE OS revision
// TODO: replace these with real values if needed
const OPTEE_MSG_REVISION_MAJOR: usize = 2;
const OPTEE_MSG_REVISION_MINOR: usize = 0;

// dummy values for OP-TEE OS UUID
// TODO: replace these with real values if needed
const OPTEE_OS_UID_0: u32 = 0x384f_b3e0;
const OPTEE_OS_UID_1: u32 = 0xe7f8_11e3;
const OPTEE_OS_UID_2: u32 = 0xaf63_0002;
const OPTEE_OS_UID_3: u32 = 0xa5d5_c51b;

const OPTEE_SMC_RETURN_OK: usize = 0x0;
const OPTEE_SMC_RETURN_ETHREAD_LIMIT: usize = 0x1;
const OPTEE_SMC_RETURN_EBUSY: usize = 0x2;
const OPTEE_SMC_RETURN_ERESUME: usize = 0x3;
const OPTEE_SMC_RETURN_EBADADDR: usize = 0x4;
const OPTEE_SMC_RETURN_EBADCMD: usize = 0x5;
const OPTEE_SMC_RETURN_ENOMEM: usize = 0x6;
const OPTEE_SMC_RETURN_ENOTAVAIL: usize = 0x7;

#[derive(Copy, Clone, PartialEq, TryFromPrimitive)]
#[non_exhaustive]
#[repr(usize)]
enum OpteeSmcReturn {
    Ok = OPTEE_SMC_RETURN_OK,
    EThreadLimit = OPTEE_SMC_RETURN_ETHREAD_LIMIT,
    EBusy = OPTEE_SMC_RETURN_EBUSY,
    EResume = OPTEE_SMC_RETURN_ERESUME,
    EBadAddr = OPTEE_SMC_RETURN_EBADADDR,
    EBadCmd = OPTEE_SMC_RETURN_EBADCMD,
    ENomem = OPTEE_SMC_RETURN_ENOMEM,
    ENotAvail = OPTEE_SMC_RETURN_ENOTAVAIL,
}

pub fn optee_smc_dispatch(optee_smc_args_pfn: u64) -> i64 {
    let Ok(_optee_smc_args_page_addr) = PhysAddr::try_new(optee_smc_args_pfn << 12) else {
        return Errno::EINVAL.as_neg().into();
    };

    // TODO: copy actual data from normal world's memory using its physical address.
    let mut optee_smc_args = OpteeSmcArgs {
        args: [0; OpteeSmcArgs::NUM_OPTEE_SMC_ARGS],
    };
    // let Some(mut optee_smc_args) = (unsafe {
    //     crate::platform_low().copy_from_vtl0_phys::<OpteeSmcArgs>(optee_smc_args_page_addr)
    // }) else {
    //     return Errno::EINVAL.as_neg().into();
    // };

    if let Ok(func_id) = optee_smc_args.func_id() {
        match func_id {
            OpteeSmcFunction::CallWithArg
            | OpteeSmcFunction::CallWithRpcArg
            | OpteeSmcFunction::CallWithRegdArg => {
                // Since we do not know whether an OP-TEE TA uses extended states, we conservatively
                // save and restore extended states before and after running any OP-TEE TA.
            }
            OpteeSmcFunction::ExchangeCapabilities => {
                optee_smc_args.set_result(
                    &OpteeSmcResult::ExchangeCapabilities {
                        status: OpteeSmcReturn::Ok,
                        capabilities: OpteeSecureWorldCapabilities::DYNAMIC_SHM
                            | OpteeSecureWorldCapabilities::MEMREF_NULL
                            | OpteeSecureWorldCapabilities::RPC_ARG,
                        max_notif_value: 0,
                        data: NUM_RPC_PARAMS,
                    },
                    None,
                );
            }
            OpteeSmcFunction::DisableShmCache => {
                optee_smc_args.set_result(
                    &OpteeSmcResult::DisableShmCache {
                        status: OpteeSmcReturn::ENotAvail,
                        shm_upper32: 0,
                        shm_lower32: 0,
                    },
                    None,
                );
            }
            OpteeSmcFunction::CallsUid => {
                optee_smc_args.set_result(
                    &OpteeSmcResult::Uuid {
                        data: [
                            OPTEE_OS_UID_0,
                            OPTEE_OS_UID_1,
                            OPTEE_OS_UID_2,
                            OPTEE_OS_UID_3,
                        ],
                    },
                    None,
                );
            }
            OpteeSmcFunction::GetOsRevision => {
                optee_smc_args.set_result(
                    &OpteeSmcResult::OsRevision {
                        major: OPTEE_MSG_REVISION_MAJOR,
                        minor: OPTEE_MSG_REVISION_MINOR,
                        build_id: 0,
                    },
                    None,
                );
            }
            OpteeSmcFunction::CallsRevision => {
                optee_smc_args.set_result(
                    &OpteeSmcResult::Revision {
                        major: OPTEE_MSG_REVISION_MAJOR,
                        minor: OPTEE_MSG_REVISION_MINOR,
                    },
                    None,
                );
            }
        }
    } else {
        return Errno::EINVAL.as_neg().into();
    }

    // TODO: Return the result by writing back the updated OP-TEE SMC arguments to VTL0's memory
    0

    // if unsafe {
    //     crate::platform_low()
    //         .copy_to_vtl0_phys::<OpteeSmcArgs>(optee_smc_args_page_addr, &optee_smc_args)
    // } {
    //     0
    // } else {
    //     Errno::EINVAL.as_neg().into()
    // }
}

/// Maintain the information of OP-TEE shared memory in VTL0 referenced by `shm_ref`.
pub(crate) struct ShmRefMap {
    inner: spin::mutex::SpinMutex<HashMap<u64, ShmRefInfo>>,
}

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

/// `ShmRefInfo` maintains the list of physical pages of shared memory.
/// `page_offset` indicates the offset within the first page (i.e., `pages[0]`).
/// Note that `pages` (including `pages[0]`) should have page-aligned physical addresses.
#[allow(dead_code)]
#[derive(Clone)]
pub struct ShmRefInfo {
    pub pages: Box<[u64]>,
    pub page_offset: u64,
}

#[allow(dead_code)]
impl ShmRefMap {
    pub fn new() -> Self {
        Self {
            inner: spin::mutex::SpinMutex::new(HashMap::new()),
        }
    }

    fn insert(&self, shm_ref: u64, info: ShmRefInfo) {
        let mut guard = self.inner.lock();
        guard.insert(shm_ref, info);
    }

    pub fn get(&self, shm_ref: u64) -> Option<ShmRefInfo> {
        let guard = self.inner.lock();
        guard.get(&shm_ref).cloned()
    }

    /// Register shared memory in VTL0 referenced by `shm_ref`.
    /// VTL0 should provide physically contiguous `ShmRefPagesData` structures starting from
    /// the page address of `phys_addr`. The page offset of `phys_addr` represents
    /// the offset within the first page of shared memory.
    pub fn register_shm(&self, phys_addr: u64, size: u64, shm_ref: u64) {
        let aligned_phys_addr = align_down(phys_addr, u64::try_from(PAGE_SIZE).unwrap());
        let page_offset = phys_addr - aligned_phys_addr;
        let aligned_size = align_up(page_offset + size, u64::try_from(PAGE_SIZE).unwrap());

        let num_pages = usize::try_from(aligned_size).unwrap() / PAGE_SIZE;
        let mut pages = Vec::with_capacity(num_pages);

        let mut pages_data_addr = aligned_phys_addr;
        loop {
            // TODO: copy actual data from normal world's memory using its physical address.
            // if let Some(pages_data) = unsafe {
            //     crate::platform_low()
            //         .copy_from_vtl0_phys::<ShmRefPagesData>(PhysAddr::new(pages_data_addr))
            // } {
            if let Some(pages_data) = {
                Some(ShmRefPagesData {
                    pages_list: [0; ShmRefPagesData::PAGELIST_ENTRIES_PER_PAGE],
                    next_page_data: 0,
                })
            } {
                for i in 0..ShmRefPagesData::PAGELIST_ENTRIES_PER_PAGE {
                    if pages_data.pages_list[i] == 0 || pages.len() == num_pages {
                        break;
                    } else if !pages_data.pages_list[i]
                        .is_multiple_of(u64::try_from(PAGE_SIZE).unwrap())
                    {
                        return;
                    } else {
                        pages.push(pages_data.pages_list[i]);
                    }
                }
                if pages_data.next_page_data == 0 || pages.len() == num_pages {
                    break;
                } else {
                    pages_data_addr = pages_data.next_page_data;
                }
            } else {
                return;
            }
        }

        self.insert(
            shm_ref,
            ShmRefInfo {
                pages: pages.into(),
                page_offset,
            },
        );
    }

    pub fn unregister_shm(&self, shm_ref: u64) {
        let mut guard = self.inner.lock();
        guard.remove(&shm_ref);
    }
}

#[allow(dead_code)]
fn shm_ref_map() -> &'static ShmRefMap {
    static SHM_REF_MAP: OnceBox<ShmRefMap> = OnceBox::new();
    SHM_REF_MAP.get_or_init(|| Box::new(ShmRefMap::new()))
}
