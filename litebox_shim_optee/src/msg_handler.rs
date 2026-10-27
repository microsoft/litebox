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
use core::mem::size_of;
use hashbrown::{HashMap, HashSet};
use litebox::mm::vmap::PhysPageAddr;
use litebox::{
    platform::{RawConstPointer, RawMutPointer},
    utils::TruncateExt,
};
use litebox_common_optee::PAGE_SIZE;
use litebox_common_optee::{
    OpteeMessageCommand, OpteeMsgArgs, OpteeMsgArgsHeader, OpteeMsgAttrType, OpteeMsgParamRmem,
    OpteeMsgParamTmem, OpteeRpcArgs, OpteeSecureWorldCapabilities, OpteeSmcArgs, OpteeSmcFunction,
    OpteeSmcResult, OpteeSmcReturnCode, TeeIdentity, TeeLogin, TeeOrigin, TeeParamType, TeeResult,
    TeeUuid, UteeEntryFunc, UteeParamOwned, UteeParams, optee_msg_args_total_size,
};
use once_cell::race::OnceBox;
use zerocopy::{FromBytes, Immutable};

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

/// Maximum TA buffer size for a single OP-TEE memref parameter.
///
/// OP-TEE OS validates memref sizes against their backing shared-memory
/// objects, but it does not define a universal ABI maximum. This is a local
/// resource policy to keep one normal-world request from consuming a large
/// fraction of the default 128 MiB memory budget.
///
/// Subject to change if the memory budget increases.
const MAX_SHM_MEMREF_SIZE: usize = 8 * 1024 * 1024;
const MAX_SHM_REF_MAP_ENTRIES: usize = 1024;

#[inline]
fn page_align_down(address: u64) -> u64 {
    address & !(PAGE_SIZE as u64 - 1)
}

#[inline]
fn page_align_up(len: u64) -> Option<u64> {
    len.checked_next_multiple_of(PAGE_SIZE as u64)
}

#[inline]
pub fn checked_memref_size(size: u64) -> Result<usize, OpteeSmcReturnCode> {
    if size > MAX_SHM_MEMREF_SIZE as u64 {
        return Err(OpteeSmcReturnCode::ENomem);
    }
    usize::try_from(size).map_err(|_| OpteeSmcReturnCode::ENomem)
}

fn parse_optee_msg_args(
    blob: &[u8],
    has_rpc_arg: bool,
) -> Result<(Box<OpteeMsgArgs>, Option<Box<OpteeRpcArgs>>), OpteeSmcReturnCode> {
    // Parse main header from the private buffer.
    let main_header = OpteeMsgArgsHeader::read_from_prefix(blob)
        .map_err(|_| OpteeSmcReturnCode::EBadAddr)?
        .0;

    // Validate num_params from the snapshot.
    if main_header.num_params as usize > OpteeMsgArgs::MAX_ARG_PARAM_COUNT {
        return Err(OpteeSmcReturnCode::EBadCmd);
    }

    let main_size = optee_msg_args_total_size(main_header.num_params);
    let main_params = &blob[size_of::<OpteeMsgArgsHeader>()..main_size];
    let main_args = OpteeMsgArgs::from_header_and_raw_params(&main_header, main_params)?;

    // Parse RPC args if present.
    // The Linux kernel driver places the RPC arg at offset main_size (based on the actual
    // num_params, not MAX_ARG_PARAM_COUNT). Since we copied main_max bytes which is >= main_size,
    // and main_size is computed from our own validated snapshot, this is safe.
    let rpc_args = if has_rpc_arg {
        let rpc_blob = &blob[main_size..];
        let rpc_header = OpteeMsgArgsHeader::read_from_prefix(rpc_blob)
            .map_err(|_| OpteeSmcReturnCode::EBadAddr)?
            .0;
        // Re-validate RPC num_params from the snapshot against our negotiated limit.
        if rpc_header.num_params as usize > OpteeRpcArgs::MAX_RPC_ARG_PARAM_COUNT {
            return Err(OpteeSmcReturnCode::EBadCmd);
        }
        let rpc_params = &rpc_blob[size_of::<OpteeMsgArgsHeader>()..];
        let rpc = OpteeRpcArgs::from_header_and_raw_params(&rpc_header, rpc_params)?;
        Some(Box::new(rpc))
    } else {
        None
    };

    Ok((Box::new(main_args), rpc_args))
}

/// Read `OpteeMsgArgs` (and optional `OpteeRpcArgs`) from a VTL0 physical address.
///
/// Copies the maximum possible size in one shot into a private VTL1 buffer, then
/// parses entirely from that buffer. This eliminates TOCTOU (double-fetch) issues:
/// VTL0 cannot mutate the data between validation and use because we only touch
/// our private copy after the single read.
///
/// The copy size is determined by known-good upper bounds, not by untrusted data:
///   - Main args: `optee_msg_args_total_size(MAX_ARG_PARAM_COUNT = 6)` = 224 bytes (the Linux
///     driver always allocates at least this much for the main arg).
///   - RPC args (when present): `optee_msg_args_total_size(rpc_num_params)`, where
///     `rpc_num_params` is our own negotiated value from `EXCHANGE_CAPABILITIES`.
///
/// If `has_rpc_arg` is true, expects an appended RPC `optee_msg_arg` immediately after
/// the main one at offset `optee_msg_args_total_size(num_params)` (the *actual* `num_params`,
/// not `MAX_ARG_PARAM_COUNT`). This matches the Linux driver's layout.
///
/// # Concurrency
///
/// This read is intentionally not serialized against a concurrent write-back on the same 4 KiB
/// frame. The Linux OP-TEE driver packs multiple `optee_msg_arg`s into sub-page slots and hands
/// out one slot per in-flight call (bitmap under `shm_arg_cache.mutex`), so concurrent cores touch
/// disjoint slots. Each access maps the frame into its own private, transient VA window (see the
/// `vmap`-based `PhysMutPtr`), so no page-table conflict arises either. A malicious normal-world
/// kernel can provide overlapped slots, but this only results in copying invalid `optee_msg_arg`
/// and/or corrupting normal-world memory - the malicious kernel can easily do these even without
/// slot overlaps. Our fallible memcpy with `FromBytes` ensures this copy-in does not result in
/// Rust safety/soundness issues.
///
/// VTL0 physical memory layout at `phys_addr`:
///
/// ```text
///  phys_addr
///  |
///  v
///  +--------+------+--------+--------+------+----------~-+
///  | header |par[0]|par[N-1]| header |par[0]|par[R-1]|xxx|
///  | 32B    | ...  |  32B   | 32B    | ...  |  32B   |xxx|
///  +--------+------+--------+--------+------+----------~-+
///  |<--- main_size -------->|<--- rpc_size --------->|   |
///  |                        ^            ^               |
///  |                 RPC starts here    main_max         |
///  |<----- copy_size = main_max + rpc_max -------------~>|
///
///  N = actual num_params from header (validated <= MAX_ARG_PARAM_COUNT after copy)
///  R = rpc_num_params (negotiated during OPTEE_SMC_EXCHANGE_CAPABILITIES)
///
///  We copy main_max + rpc_max bytes (the upper bound), which covers the
///  actual data (main_size + rpc_size) plus some unused area between
///  main_size and main_max. We parse using main_size from our private
///  snapshot, so the RPC arg is found at its correct offset.
/// ```
///
/// Returns `(main_args, Option<rpc_args>)`.
pub fn read_optee_msg_args_from_phys<Platform: crate::OpteeShimPlatform>(
    platform: &Platform,
    phys_addr: usize,
    has_rpc_arg: bool,
) -> Result<(Box<OpteeMsgArgs>, Option<Box<OpteeRpcArgs>>), OpteeSmcReturnCode> {
    // Compute copy size from known-good upper bounds — no untrusted data involved.
    let main_max = optee_msg_args_total_size(OpteeMsgArgs::MAX_ARG_PARAM_COUNT.trunc());
    let copy_size = if has_rpc_arg {
        main_max + optee_msg_args_total_size(OpteeRpcArgs::MAX_RPC_ARG_PARAM_COUNT.trunc())
    } else {
        main_max
    };

    let mut blob = alloc::vec![0u8; copy_size];

    let blob_ptr = NormalWorldConstPtr::<Platform, u8, PAGE_SIZE>::with_contiguous_pages(
        platform, phys_addr, copy_size,
    )
    .map_err(|_| OpteeSmcReturnCode::EBadAddr)?;
    blob_ptr
        .read_slice_at_offset(0, &mut blob)
        .map_err(|_| OpteeSmcReturnCode::EBadAddr)?;

    parse_optee_msg_args(&blob, has_rpc_arg)
}

/// Read main and RPC arguments from an explicitly identified registered SHM view.
#[allow(clippy::type_complexity)]
pub fn read_optee_msg_args_from_regd_shm<Platform: litebox::mm::vmap::VmapManager<PAGE_SIZE>>(
    platform: &Platform,
    shm_ref: u64,
    offset: usize,
) -> Result<(Box<OpteeMsgArgs>, Option<Box<OpteeRpcArgs>>, u64), OpteeSmcReturnCode> {
    let shm_info = shm_ref_map()
        .get(shm_ref)
        .ok_or(OpteeSmcReturnCode::EBadAddr)?;
    let main_max = optee_msg_args_total_size(OpteeMsgArgs::MAX_ARG_PARAM_COUNT.trunc());
    let copy_size =
        main_max + optee_msg_args_total_size(OpteeRpcArgs::MAX_RPC_ARG_PARAM_COUNT.trunc());
    let mut blob = alloc::vec![0u8; copy_size];
    shm_info.read_at(platform, offset, &mut blob)?;
    let (msg_args, rpc_args) = parse_optee_msg_args(&blob, true)?;

    let total_offset = shm_info
        .page_offset
        .checked_add(offset)
        .ok_or(OpteeSmcReturnCode::EBadAddr)?;
    let page_index = total_offset / PAGE_SIZE;
    let offset_in_page = total_offset % PAGE_SIZE;
    let msg_args_phys_addr = shm_info
        .page_addrs
        .get(page_index)
        .ok_or(OpteeSmcReturnCode::EBadAddr)?
        .as_usize()
        .checked_add(offset_in_page)
        .ok_or(OpteeSmcReturnCode::EBadAddr)? as u64;

    Ok((msg_args, rpc_args, msg_args_phys_addr))
}

/// Register a page-list-backed TMEM allocation returned by normal world.
pub fn register_rpc_shm<Platform: litebox::mm::vmap::VmapManager<PAGE_SIZE>>(
    platform: &Platform,
    tmem: &OpteeMsgParamTmem,
) -> Result<(), OpteeSmcReturnCode> {
    checked_memref_size(tmem.size)?;
    let pages_data_phys_addr = page_align_down(tmem.buf_ptr);
    let page_offset = tmem
        .buf_ptr
        .checked_sub(pages_data_phys_addr)
        .ok_or(OpteeSmcReturnCode::EBadAddr)?;
    let total_size = page_offset
        .checked_add(tmem.size)
        .ok_or(OpteeSmcReturnCode::EBadAddr)?;
    let aligned_size = page_align_up(total_size).ok_or(OpteeSmcReturnCode::EBadAddr)?;
    shm_ref_map().register_shm(
        platform,
        pages_data_phys_addr,
        page_offset,
        tmem.size,
        aligned_size,
        tmem.shm_ref,
    )
}

/// Remove a shared-memory mapping inserted for an RPC allocation.
pub fn unregister_rpc_shm(shm_ref: u64) -> bool {
    shm_ref_map().remove(shm_ref).is_some()
}

/// Copy bytes from a registered RPC allocation into trusted memory.
pub fn read_rpc_shm<Platform: litebox::mm::vmap::VmapManager<PAGE_SIZE>>(
    platform: &Platform,
    shm_ref: u64,
    offset: usize,
    buffer: &mut [u8],
) -> Result<(), OpteeSmcReturnCode> {
    shm_ref_map()
        .get(shm_ref)
        .ok_or(OpteeSmcReturnCode::EBadAddr)?
        .read_at(platform, offset, buffer)
}

/// This function handles `OpteeSmcArgs` passed from the normal world (VTL0) via an OP-TEE SMC call.
/// It returns an `OpteeSmcResult` representing the result of the SMC call or `OpteeMsgArgs` it contains
/// if the SMC call involves with an OP-TEE message which should be handled by
/// `handle_optee_msg_args` or `handle_ta_request`.
pub fn handle_optee_smc_args<'a, Platform: crate::OpteeShimPlatform>(
    platform: &Platform,
    smc: &'a mut OpteeSmcArgs,
) -> Result<OpteeSmcResult<'a>, OpteeSmcReturnCode> {
    let func_id = smc.func_id()?;
    #[cfg(debug_assertions)]
    litebox_util_log::debug!(
        func_id:? = func_id;
        "OP-TEE SMC function"
    );
    match func_id {
        OpteeSmcFunction::CallWithArg => {
            let msg_args_addr = smc.optee_msg_args_phys_addr()?;
            let msg_args_addr: usize = msg_args_addr.trunc();
            let (msg_args, _) = read_optee_msg_args_from_phys(platform, msg_args_addr, false)?;
            Ok(OpteeSmcResult::CallWithArg {
                msg_args,
                rpc_args: None,
                msg_args_phys_addr: msg_args_addr as u64,
            })
        }
        OpteeSmcFunction::CallWithRpcArg => {
            let msg_args_addr = smc.optee_msg_args_phys_addr()?;
            let msg_args_addr: usize = msg_args_addr.trunc();
            let (msg_args, rpc_args) =
                read_optee_msg_args_from_phys(platform, msg_args_addr, true)?;
            Ok(OpteeSmcResult::CallWithArg {
                msg_args,
                rpc_args,
                msg_args_phys_addr: msg_args_addr as u64,
            })
        }
        OpteeSmcFunction::ReturnFromRpc => Err(OpteeSmcReturnCode::EBadCmd),
        OpteeSmcFunction::CallWithRegdArg => {
            // `OpteeMsgArgs` is located at the offset specified in args[3] within the shared memory region pointed by args[1]:args[2].
            let (shm_ref, offset) = smc.optee_regd_shm_ref_and_offset()?;
            let (msg_args, rpc_args, msg_args_phys_addr) =
                read_optee_msg_args_from_regd_shm(platform, shm_ref, offset)?;

            Ok(OpteeSmcResult::CallWithArg {
                msg_args,
                rpc_args,
                msg_args_phys_addr,
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
                data: OpteeRpcArgs::MAX_RPC_ARG_PARAM_COUNT,
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
pub fn handle_optee_msg_args<Platform: crate::OpteeShimPlatform>(
    platform: &Platform,
    msg_args: &OpteeMsgArgs,
) -> Result<(), OpteeSmcReturnCode> {
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
            let page_offset = tmem
                .buf_ptr
                .checked_sub(shm_ref_pages_data_phys_addr)
                .ok_or(OpteeSmcReturnCode::EBadAddr)?;
            let size = page_offset
                .checked_add(tmem.size)
                .ok_or(OpteeSmcReturnCode::ENomem)?;
            let aligned_size = page_align_up(size).ok_or(OpteeSmcReturnCode::ENomem)?;
            shm_ref_map().register_shm(
                platform,
                shm_ref_pages_data_phys_addr,
                page_offset,
                tmem.size,
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
            #[cfg(debug_assertions)]
            todo!("Unimplemented OpteeMessageCommand: {:?}", msg_args.cmd);
            #[cfg(not(debug_assertions))]
            {
                litebox_util_log::debug!(cmd:? = msg_args.cmd; "Unimplemented OpteeMessageCommand");
                return Err(OpteeSmcReturnCode::EBadCmd);
            }
        }
    }
    Ok(())
}

/// A TA request, decoded from an OP-TEE message or built with [`Self::new`].
///
/// `shm_info` holds the normal-world memory of each memref param. Loading the request
/// into a TA entry records where the shim placed `params` in TA memory; write-back reads
/// TA outputs only through that record.
pub struct TaRequestInfo<const ALIGN: usize> {
    pub uuid: Option<TeeUuid>,
    pub client_identity: Option<TeeIdentity>,
    pub session: u32,
    pub entry_func: UteeEntryFunc,
    pub cmd_id: u32,
    pub params: [UteeParamOwned; UteeParamOwned::TEE_NUM_PARAMS],
    pub shm_info: [Option<ShmInfo<ALIGN>>; UteeParamOwned::TEE_NUM_PARAMS],
    /// Placement of `params` in TA memory, recorded by
    /// [`load_ta_context`](crate::OpteeShimEntrypoints::load_ta_context); `None` until then.
    pub(crate) ta_layout: Option<crate::TaParamLayout>,
}

impl<const ALIGN: usize> TaRequestInfo<ALIGN> {
    /// A request without normal-world memory: no UUID, client identity, `shm_info`, or params.
    #[must_use]
    pub fn new(entry_func: UteeEntryFunc, session: u32, cmd_id: u32) -> Self {
        Self {
            uuid: None,
            client_identity: None,
            session,
            entry_func,
            cmd_id,
            params: [const { UteeParamOwned::None }; UteeParamOwned::TEE_NUM_PARAMS],
            shm_info: [const { None }; UteeParamOwned::TEE_NUM_PARAMS],
            ta_layout: None,
        }
    }

    /// Address of the TA's `UteeParams` block, once the request is loaded into a TA entry.
    #[must_use]
    pub fn ta_params_address(&self) -> Option<usize> {
        self.ta_layout.map(|layout| layout.params_address)
    }

    /// `(address, len)` of the TA buffer for memref output or inout parameter `index`, once loaded.
    #[must_use]
    pub fn ta_memref_buffer(&self, index: usize) -> Option<(usize, usize)> {
        self.ta_layout?.memref_buffers.get(index).copied().flatten()
    }
}

/// This function decodes a TA request contained in `OpteeMsgArgs`.
///
/// Memref payload copies are deferred until their TA buffers are allocated.
pub fn decode_ta_request<Platform: crate::OpteeShimPlatform>(
    _platform: &Platform,
    msg_args: &OpteeMsgArgs,
) -> Result<TaRequestInfo<PAGE_SIZE>, OpteeSmcReturnCode> {
    let ta_entry_func: UteeEntryFunc = msg_args.cmd.try_into()?;
    let num_params =
        usize::try_from(msg_args.num_params).map_err(|_| OpteeSmcReturnCode::EBadCmd)?;
    if ta_entry_func == UteeEntryFunc::OpenSession {
        if num_params < 2 || num_params - 2 > UteeParamOwned::TEE_NUM_PARAMS {
            return Err(OpteeSmcReturnCode::EBadCmd);
        }
    } else if num_params > UteeParamOwned::TEE_NUM_PARAMS {
        return Err(OpteeSmcReturnCode::EBadCmd);
    }

    let (ta_uuid, client_identity, skip): (Option<TeeUuid>, Option<TeeIdentity>, usize) =
        if ta_entry_func == UteeEntryFunc::OpenSession {
            // If it is an OpenSession request, extract the TA UUID, client UUID,
            // and login from the two meta params. Wire layout (per the Linux
            // OP-TEE driver):
            // - params[0].a/b = TA UUID (two little-endian u64 values)
            // - params[1].a/b = client UUID, but only meaningful for the
            //   user/group/application logins; PUBLIC/REE_KERNEL ignore it and
            //   report the nil UUID (see the match below).
            // - params[1].c = client login type (TEE_LOGIN_*)
            let param0 = msg_args.get_meta_param_value(0)?;
            let ta_data = [param0.a, param0.b];

            let param1 = msg_args.get_meta_param_value(1)?;
            let login: u32 = param1.c.trunc();
            // Reject unknown login methods
            let login = TeeLogin::try_from(login).map_err(|_| OpteeSmcReturnCode::EBadCmd)?;

            // Only the REE-derived user/group/application logins carry a
            // meaningful client UUID. PUBLIC and REE_KERNEL clients are anonymous
            // and must report the nil UUID (OP-TEE OS memsets it to zero).
            // TRUSTED_APP identifies a TA-to-TA caller and is established
            // internally, never from a normal-world message.
            let client_uuid = match login {
                TeeLogin::Public | TeeLogin::ReeKernel => TeeUuid::NIL,
                TeeLogin::User
                | TeeLogin::Group
                | TeeLogin::Application
                | TeeLogin::ApplicationUser
                | TeeLogin::ApplicationGroup => TeeUuid::from_u64_array([param1.a, param1.b]),
                TeeLogin::TrustedApp => return Err(OpteeSmcReturnCode::EBadCmd),
            };

            // Skip the first two parameters as they convey TA and client UUIDs
            (
                Some(TeeUuid::from_u64_array(ta_data)),
                Some(TeeIdentity {
                    login,
                    uuid: client_uuid,
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
        shm_info: [const { None }; UteeParamOwned::TEE_NUM_PARAMS],
        ta_layout: None,
    };

    if num_params
        .checked_sub(skip)
        .is_none_or(|n| n > UteeParamOwned::TEE_NUM_PARAMS)
    {
        return Err(OpteeSmcReturnCode::EBadCmd);
    }
    for (i, param) in msg_args
        .params
        .iter()
        .take(num_params)
        .skip(skip)
        .enumerate()
    {
        // The meta bit marks the OpenSession TA-UUID/client-identity params,
        // which were already consumed via `skip`. A client parameter must not
        // carry it (mirrors OP-TEE OS `copy_in_params`).
        if param.is_meta() {
            return Err(OpteeSmcReturnCode::EBadCmd);
        }
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
                ta_req_info.shm_info[i] = Some(shm_info);
                UteeParamOwned::MemrefInput { data: None }
            }
            OpteeMsgAttrType::RmemInput => {
                let rmem = param.get_param_rmem().ok_or(OpteeSmcReturnCode::EBadCmd)?;
                let shm_info = get_shm_info_from_optee_msg_param_rmem(rmem)?;
                ta_req_info.shm_info[i] = Some(shm_info);
                UteeParamOwned::MemrefInput { data: None }
            }
            OpteeMsgAttrType::TmemOutput => {
                let tmem = param.get_param_tmem().ok_or(OpteeSmcReturnCode::EBadCmd)?;
                let shm_info = get_shm_info_from_optee_msg_param_tmem(tmem)?;
                let buffer_size = shm_info.len();

                ta_req_info.shm_info[i] = Some(shm_info);
                UteeParamOwned::MemrefOutput { buffer_size }
            }
            OpteeMsgAttrType::RmemOutput => {
                let rmem = param.get_param_rmem().ok_or(OpteeSmcReturnCode::EBadCmd)?;
                let shm_info = get_shm_info_from_optee_msg_param_rmem(rmem)?;
                let buffer_size = shm_info.len();

                ta_req_info.shm_info[i] = Some(shm_info);
                UteeParamOwned::MemrefOutput { buffer_size }
            }
            OpteeMsgAttrType::TmemInout => {
                let tmem = param.get_param_tmem().ok_or(OpteeSmcReturnCode::EBadCmd)?;
                let shm_info = get_shm_info_from_optee_msg_param_tmem(tmem)?;
                let buffer_size = shm_info.len();

                ta_req_info.shm_info[i] = Some(shm_info);
                UteeParamOwned::MemrefInout {
                    data: None,
                    buffer_size,
                }
            }
            OpteeMsgAttrType::RmemInout => {
                let rmem = param.get_param_rmem().ok_or(OpteeSmcReturnCode::EBadCmd)?;
                let shm_info = get_shm_info_from_optee_msg_param_rmem(rmem)?;
                let buffer_size = shm_info.len();

                ta_req_info.shm_info[i] = Some(shm_info);
                UteeParamOwned::MemrefInout {
                    data: None,
                    buffer_size,
                }
            }
            _ => return Err(OpteeSmcReturnCode::EBadCmd),
        };
    }

    Ok(ta_req_info)
}

/// TA outputs for [`write_back`].
///
/// Output kinds come from `request`, never from `UteeParams::types`, which a TA
/// can rewrite.
#[derive(Clone, Copy)]
pub(crate) enum ParamOutputs<'a> {
    /// TA entry: `UteeParams` and memref data are in TA memory, at the placement
    /// recorded in the request.
    Ta(&'a TaRequestInfo<PAGE_SIZE>),
    /// Client PTA: values and sizes are in `params`; memref data is already in
    /// shared memory.
    ClientPta {
        request: &'a TaRequestInfo<PAGE_SIZE>,
        params: &'a UteeParams,
    },
}

/// A validated copy of memref output data from TA memory to shared memory.
struct MemrefCopy<'a> {
    src: usize,
    dst: &'a ShmInfo<PAGE_SIZE>,
    len: usize,
}

/// Update the OP-TEE message arguments for returning from the secure world to the normal world.
///
/// Like OP-TEE `copy_out_param`, outputs follow the request's param types for every
/// result, except that `TargetDead` writes back only the result. A NULL memref has
/// neither data nor a buffer to bound, so its size is reported as is.
///
/// # Errors
///
/// Fails if a `Success` memref size exceeds its shared memory (clients may trust it),
/// TA memory cannot be read, or a copy fails. `msg_args` is then unchanged, but memref
/// data copied before the failure stays in shared memory.
///
/// # Panics
///
/// Panics if `request` was not loaded with
/// [`load_ta_context`](crate::OpteeShimEntrypoints::load_ta_context), unless
/// `return_code` is `TargetDead`.
pub fn update_optee_msg_args<Platform: crate::OpteeShimPlatform>(
    platform: &Platform,
    return_code: TeeResult,
    return_origin: TeeOrigin,
    session_id: Option<u32>,
    request: Option<&TaRequestInfo<PAGE_SIZE>>,
    msg_args: &mut OpteeMsgArgs,
) -> Result<(), OpteeSmcReturnCode> {
    write_back(
        platform,
        return_code,
        return_origin,
        session_id,
        request.map(ParamOutputs::Ta),
        msg_args,
    )
}

/// [`update_optee_msg_args`] with explicit output sources.
pub(crate) fn write_back<Platform: crate::OpteeShimPlatform>(
    platform: &Platform,
    return_code: TeeResult,
    return_origin: TeeOrigin,
    session_id: Option<u32>,
    outputs: Option<ParamOutputs<'_>>,
    msg_args: &mut OpteeMsgArgs,
) -> Result<(), OpteeSmcReturnCode> {
    let mut staged = *msg_args;
    staged.ret = return_code;
    staged.ret_origin = return_origin;
    if let Some(session_id) = session_id {
        staged.session = session_id;
    }
    // A dead TA's memory must not be read.
    if let Some(outputs) = outputs
        && return_code != TeeResult::TargetDead
    {
        let copies = stage_outputs::<Platform>(outputs, return_code, &mut staged)?;
        for copy in copies.iter().flatten() {
            let src = crate::UserConstPtr::<Platform, u8>::from_usize(copy.src);
            copy.dst.copy_from_user(platform, src, copy.len)?;
        }
    }
    *msg_args = staged;
    Ok(())
}

/// Write the outputs into `msg_args` and return the memref copies to perform.
///
/// Reads TA memory for [`ParamOutputs::Ta`], so the TA must not be dead.
fn stage_outputs<'a, Platform: crate::OpteeShimPlatform>(
    outputs: ParamOutputs<'a>,
    return_code: TeeResult,
    msg_args: &mut OpteeMsgArgs,
) -> Result<[Option<MemrefCopy<'a>>; UteeParams::TEE_NUM_PARAMS], OpteeSmcReturnCode> {
    let mut copies = [const { None }; UteeParams::TEE_NUM_PARAMS];
    let (request, params, layout) = match outputs {
        ParamOutputs::Ta(request) => {
            let layout = request
                .ta_layout
                .expect("request is loaded before write-back");
            // Single fetch: the TA owns this memory.
            let params =
                crate::UserConstPtr::<Platform, UteeParams>::from_usize(layout.params_address)
                    .read_at_offset(0)
                    .ok_or(OpteeSmcReturnCode::EBadAddr)?;
            (request, params, Some(layout))
        }
        ParamOutputs::ClientPta { request, params } => (request, *params, None),
    };
    let wire_param_offset = if request.entry_func == UteeEntryFunc::OpenSession {
        2
    } else {
        0
    };
    for (index, param) in request.params.iter().enumerate() {
        let wire_index = index + wire_param_offset;
        // For a memref, `vals[2 * index]` is a TA-written address and is ignored.
        let (value_a, value_b) = (params.vals[2 * index], params.vals[2 * index + 1]);
        match param {
            UteeParamOwned::ValueOutput | UteeParamOwned::ValueInout { .. } => {
                // `c` is preserved, as in OP-TEE `copy_out_param`.
                let mut value = msg_args.get_param_value(wire_index)?;
                value.a = value_a;
                value.b = value_b;
                msg_args.set_param_value(wire_index, value)?;
            }
            UteeParamOwned::MemrefOutput { .. } | UteeParamOwned::MemrefInout { .. } => {
                let dst = request.shm_info[index]
                    .as_ref()
                    .ok_or(OpteeSmcReturnCode::EBadAddr)?;
                let fitting_len = usize::try_from(value_b)
                    .ok()
                    .filter(|&len| len <= dst.len());
                if dst.is_null() {
                    // Nothing to copy, and no buffer for the size to bound.
                } else if let Some(len) = fitting_len {
                    if let Some(layout) = layout {
                        // The recorded buffer bounds the read even if `request.params` changed.
                        let (src, _) = layout.memref_buffers[index]
                            .filter(|&(_, buf_len)| len <= buf_len)
                            .ok_or(OpteeSmcReturnCode::EBadAddr)?;
                        copies[index] = Some(MemrefCopy { src, dst, len });
                    }
                } else if return_code == TeeResult::Success {
                    // A client may trust a `Success` size to bound its reads.
                    return Err(OpteeSmcReturnCode::EBadAddr);
                }
                msg_args.set_param_memref_size(wire_index, value_b)?;
            }
            UteeParamOwned::None
            | UteeParamOwned::ValueInput { .. }
            | UteeParamOwned::MemrefInput { .. } => {}
        }
    }
    Ok(copies)
}

/// Build `UteeParams` for a client PTA from a decoded request.
///
/// Memref addresses are 0: the buffer is `ta_req_info.shm_info[i]`, whose
/// length equals the memref size.
pub(crate) fn client_pta_params(ta_req_info: &TaRequestInfo<PAGE_SIZE>) -> UteeParams {
    let mut params = UteeParams::new();
    for (index, param) in ta_req_info.params.iter().enumerate() {
        let shm_len = || ta_req_info.shm_info[index].as_ref().map_or(0, ShmInfo::len) as u64;
        let (param_type, a, b) = match param {
            UteeParamOwned::None => (TeeParamType::None, 0, 0),
            UteeParamOwned::ValueInput { value_a, value_b } => {
                (TeeParamType::ValueInput, *value_a, *value_b)
            }
            UteeParamOwned::ValueOutput => (TeeParamType::ValueOutput, 0, 0),
            UteeParamOwned::ValueInout { value_a, value_b } => {
                (TeeParamType::ValueInout, *value_a, *value_b)
            }
            UteeParamOwned::MemrefInput { .. } => (TeeParamType::MemrefInput, 0, shm_len()),
            UteeParamOwned::MemrefOutput { buffer_size } => {
                (TeeParamType::MemrefOutput, 0, *buffer_size as u64)
            }
            UteeParamOwned::MemrefInout { buffer_size, .. } => {
                (TeeParamType::MemrefInout, 0, *buffer_size as u64)
            }
        };
        params
            .set_type(index, param_type)
            .expect("index is in range");
        params.set_values(index, a, b).expect("index is in range");
    }
    params
}

/// A scatter-gather list of OP-TEE physical page addresses in the normal world (VTL0) to
/// share with the secure world (VTL1). Each [`ShmRefPagesData`] occupies one memory page
/// where `pages_list` contains a list of physical page addresses and `next_page_data`
/// contains the physical address of the next [`ShmRefPagesData`] if any. Entries of `pages_list`
/// and `next_page_data` contain zero if the list ends. These physical page addresses are
/// virtually contiguous in the normal world. All these address values must be page aligned.
///
/// `pages_data` from [Linux](https://elixir.bootlin.com/linux/v6.18.2/source/drivers/tee/optee/smc_abi.c#L409)
#[derive(Clone, Copy, FromBytes, Immutable)]
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
/// `len` is the byte length of the shared memory view starting at `page_offset`.
/// `null` marks a NULL memref (`OPTEE_SMC_SEC_CAP_MEMREF_NULL`). Being empty, it rejects any
/// non-empty access even where `null` is unchecked.
#[derive(Clone)]
pub struct ShmInfo<const ALIGN: usize> {
    page_addrs: Box<[PhysPageAddr<ALIGN>]>,
    page_offset: usize,
    len: usize,
    null: bool,
}

impl<const ALIGN: usize> ShmInfo<ALIGN> {
    pub fn new(
        page_addrs: Box<[PhysPageAddr<ALIGN>]>,
        page_offset: usize,
        len: usize,
    ) -> Result<Self, OpteeSmcReturnCode> {
        if page_offset >= ALIGN {
            return Err(OpteeSmcReturnCode::EBadAddr);
        }
        if len
            > page_addrs
                .len()
                .checked_mul(ALIGN)
                .and_then(|size| size.checked_sub(page_offset))
                .ok_or(OpteeSmcReturnCode::EBadAddr)?
        {
            return Err(OpteeSmcReturnCode::EBadAddr);
        }
        Ok(Self {
            page_addrs,
            page_offset,
            len,
            null: false,
        })
    }

    pub(crate) fn is_null(&self) -> bool {
        self.null
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }

    /// Read into `buffer` from the normal-world shared memory pages referenced by `self`,
    /// starting at byte `offset` within the view.
    /// Returns `EBadAddr` if the requested range is not entirely within the view.
    fn read_at<Platform: litebox::mm::vmap::VmapManager<ALIGN>>(
        &self,
        platform: &Platform,
        offset: usize,
        buffer: &mut [u8],
    ) -> Result<(), OpteeSmcReturnCode> {
        if offset
            .checked_add(buffer.len())
            .is_none_or(|end| end > self.len)
        {
            return Err(OpteeSmcReturnCode::EBadAddr);
        }
        if buffer.is_empty() {
            return Ok(());
        }
        let ptr = NormalWorldConstPtr::<Platform, u8, ALIGN>::new(
            platform,
            &self.page_addrs,
            self.page_offset,
        )?;
        ptr.read_slice_at_offset(offset, buffer)?;
        Ok(())
    }

    /// Write `data` to the normal-world shared memory pages referenced by `self`,
    /// starting at byte `offset` within the view.
    /// Returns `EBadAddr` if the requested range is not entirely within the view.
    pub(super) fn write_at<Platform: litebox::mm::vmap::VmapManager<ALIGN>>(
        &self,
        platform: &Platform,
        offset: usize,
        data: &[u8],
    ) -> Result<(), OpteeSmcReturnCode> {
        if offset
            .checked_add(data.len())
            .is_none_or(|end| end > self.len)
        {
            return Err(OpteeSmcReturnCode::EBadAddr);
        }
        if data.is_empty() {
            return Ok(());
        }
        let ptr = NormalWorldMutPtr::<Platform, u8, ALIGN>::new(
            platform,
            &self.page_addrs,
            self.page_offset,
        )?;
        ptr.write_slice_at_offset(offset, data)?;
        Ok(())
    }

    /// Copy from this normal-world shared memory into TA userspace.
    pub(crate) fn copy_to_user<Platform>(
        &self,
        platform: &Platform,
        dst: crate::UserMutPtr<Platform, u8>,
        len: usize,
    ) -> Result<(), OpteeSmcReturnCode>
    where
        Platform: crate::OpteeShimPlatform + litebox::mm::vmap::VmapManager<ALIGN>,
    {
        if len > self.len {
            return Err(OpteeSmcReturnCode::EBadAddr);
        }
        if len == 0 {
            return Ok(());
        }
        let mut offset = 0;
        let mut buffer = [0u8; PAGE_SIZE];
        while offset < len {
            let chunk_len = (len - offset).min(buffer.len());
            self.read_at(platform, offset, &mut buffer[..chunk_len])?;
            dst.copy_from_slice(offset, &buffer[..chunk_len])
                .ok_or(OpteeSmcReturnCode::EBadAddr)?;
            offset += chunk_len;
        }
        Ok(())
    }

    /// Copy from TA userspace into this normal-world shared memory.
    fn copy_from_user<Platform>(
        &self,
        platform: &Platform,
        src: crate::UserConstPtr<Platform, u8>,
        len: usize,
    ) -> Result<(), OpteeSmcReturnCode>
    where
        Platform: crate::OpteeShimPlatform + litebox::mm::vmap::VmapManager<ALIGN>,
    {
        if len > self.len {
            return Err(OpteeSmcReturnCode::EBadAddr);
        }
        if len == 0 {
            return Ok(());
        }
        let ptr = NormalWorldMutPtr::<Platform, u8, ALIGN>::new(
            platform,
            &self.page_addrs,
            self.page_offset,
        )?;
        let mut offset = 0;
        while offset < len {
            let chunk_len = (len - offset).min(PAGE_SIZE);
            let address = src
                .as_usize()
                .checked_add(offset)
                .ok_or(OpteeSmcReturnCode::EBadAddr)?;
            let chunk = crate::UserConstPtr::<Platform, u8>::from_usize(address)
                .to_owned_slice(chunk_len)
                .ok_or(OpteeSmcReturnCode::EBadAddr)?;
            ptr.write_slice_at_offset(offset, &chunk)?;
            offset += chunk_len;
        }
        Ok(())
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
    fn new() -> Self {
        Self {
            inner: spin::mutex::SpinMutex::new(HashMap::new()),
        }
    }

    fn insert(&self, shm_ref: u64, info: ShmInfo<ALIGN>) -> Result<(), OpteeSmcReturnCode> {
        let mut guard = self.inner.lock();
        if guard.contains_key(&shm_ref) {
            Err(OpteeSmcReturnCode::ENotAvail)
        } else if guard.len() >= MAX_SHM_REF_MAP_ENTRIES {
            Err(OpteeSmcReturnCode::ENomem)
        } else {
            let _ = guard.insert(shm_ref, info);
            Ok(())
        }
    }

    fn remove(&self, shm_ref: u64) -> Option<ShmInfo<ALIGN>> {
        let mut guard = self.inner.lock();
        guard.remove(&shm_ref)
    }

    fn get(&self, shm_ref: u64) -> Option<ShmInfo<ALIGN>> {
        let guard = self.inner.lock();
        guard.get(&shm_ref).cloned()
    }

    /// This function registers shared memory information that the normal world (VTL0) provides.
    /// Specifically, it walks through a linked list of [`ShmRefPagesData`] structures referenced by
    /// `shm_ref_pages_data_phys_addr` to create a slice of the shared physical page addresses
    /// and registers the slice with `shm_ref` as its identifier. `page_offset` indicates
    /// the page offset of the first page (i.e., `pages_list[0]` of the first [`ShmRefPagesData`]).
    /// `size` is the user-visible byte length of the shared memory view starting at `page_offset`;
    /// this is the bound enforced on subsequent reads/writes via the registered [`ShmInfo`].
    /// `aligned_size` indicates the page-aligned size of the shared memory region to register
    /// (i.e., `page_align_up(page_offset + size)`) and determines how many physical pages are
    /// walked from the [`ShmRefPagesData`] list.
    fn register_shm<Platform: litebox::mm::vmap::VmapManager<ALIGN>>(
        &self,
        platform: &Platform,
        shm_ref_pages_data_phys_addr: u64,
        page_offset: u64,
        size: u64,
        aligned_size: u64,
        shm_ref: u64,
    ) -> Result<(), OpteeSmcReturnCode> {
        if page_offset >= ALIGN as u64 || aligned_size == 0 {
            return Err(OpteeSmcReturnCode::EBadAddr);
        }
        let size: usize = size.trunc();
        let aligned_size_usize: usize = aligned_size.trunc();
        if aligned_size_usize > MAX_SHM_MEMREF_SIZE {
            return Err(OpteeSmcReturnCode::ENomem);
        }
        let num_pages = aligned_size_usize / ALIGN;
        let mut pages = Vec::with_capacity(num_pages);
        let mut visited_pages_data = HashSet::new();
        let mut cur_addr: usize = shm_ref_pages_data_phys_addr.trunc();
        loop {
            if visited_pages_data.contains(&cur_addr) {
                return Err(OpteeSmcReturnCode::EBadAddr);
            }
            visited_pages_data.insert(cur_addr);
            let cur_ptr = NormalWorldConstPtr::<Platform, ShmRefPagesData, ALIGN>::with_usize(
                platform, cur_addr,
            )
            .map_err(|_| OpteeSmcReturnCode::EBadAddr)?;
            let pages_data = cur_ptr
                .read_at_offset(0)
                .map_err(|_| OpteeSmcReturnCode::EBadAddr)?;
            let pages_len_before = pages.len();
            for page in &pages_data.pages_list {
                if *page == 0 || pages.len() == num_pages {
                    break;
                } else {
                    pages.push(
                        PhysPageAddr::new((*page).trunc()).ok_or(OpteeSmcReturnCode::EBadAddr)?,
                    );
                }
            }
            if pages.len() == num_pages {
                break;
            }
            if pages.len() == pages_len_before || pages_data.next_page_data == 0 {
                return Err(OpteeSmcReturnCode::EBadAddr);
            }
            if pages_data.next_page_data.is_multiple_of(ALIGN as u64) {
                cur_addr = pages_data.next_page_data.trunc();
            } else {
                return Err(OpteeSmcReturnCode::EBadAddr);
            }
        }

        self.insert(
            shm_ref,
            ShmInfo::new(pages.into_boxed_slice(), page_offset.trunc(), size)?,
        )?;
        Ok(())
    }
}

/// Serialize RPC arguments immediately after the main message in registered shared memory.
pub fn write_rpc_args_to_regd_shm<Platform: litebox::mm::vmap::VmapManager<PAGE_SIZE>>(
    platform: &Platform,
    shm_ref: u64,
    msg_args_offset: usize,
    msg_args_num_params: u32,
    rpc_args: &OpteeRpcArgs,
) -> Result<(), OpteeSmcReturnCode> {
    let shm_info = shm_ref_map()
        .get(shm_ref)
        .ok_or(OpteeSmcReturnCode::EBadAddr)?;
    let rpc_args_offset = msg_args_offset
        .checked_add(optee_msg_args_total_size(msg_args_num_params))
        .ok_or(OpteeSmcReturnCode::EBadAddr)?;
    let rpc_args_size = optee_msg_args_total_size(rpc_args.num_params);
    let mut blob = alloc::vec![0u8; rpc_args_size];
    rpc_args.serialize(&mut blob)?;
    shm_info.write_at(platform, rpc_args_offset, &blob)
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
        // The client's size is ignored, like OP-TEE OS `set_tmem_param()`.
        return Ok(ShmInfo {
            page_addrs: Box::new([]),
            page_offset: 0,
            len: 0,
            null: true,
        });
    }

    let phys_addr = tmem.buf_ptr;
    let size = checked_memref_size(tmem.size)?;

    // Calculate page-aligned address and offset
    let phys_addr_usize: usize = phys_addr.trunc();
    let page_offset = phys_addr_usize % PAGE_SIZE;
    let aligned_addr = phys_addr - page_offset as u64;

    // Calculate number of pages needed
    let num_pages = page_offset
        .checked_add(size)
        .ok_or(OpteeSmcReturnCode::EBadAddr)?
        .div_ceil(PAGE_SIZE);

    // Build page address list
    let mut page_addrs = Vec::with_capacity(num_pages);
    for i in 0..num_pages {
        let page_addr = aligned_addr
            .checked_add(
                i.checked_mul(PAGE_SIZE)
                    .ok_or(OpteeSmcReturnCode::EBadAddr)? as u64,
            )
            .ok_or(OpteeSmcReturnCode::EBadAddr)?;
        page_addrs.push(PhysPageAddr::new(page_addr.trunc()).ok_or(OpteeSmcReturnCode::EBadAddr)?);
    }

    ShmInfo::new(page_addrs.into_boxed_slice(), page_offset, size)
}

/// Get the normal world shared memory information (physical addresses and page offset) from `OpteeMsgParamRmem`.
///
/// `rmem.offs` must be an offset within the shared memory region registered with `rmem.shm_ref` before
/// and `rmem.offs + rmem.size` must not exceed the size of the registered shared memory region.
fn get_shm_info_from_optee_msg_param_rmem(
    rmem: OpteeMsgParamRmem,
) -> Result<ShmInfo<PAGE_SIZE>, OpteeSmcReturnCode> {
    let size = checked_memref_size(rmem.size)?;
    let Some(shm_info) = shm_ref_map().get(rmem.shm_ref) else {
        return Err(OpteeSmcReturnCode::ENotAvail);
    };
    let page_offset = shm_info.page_offset;
    let rmem_offs: usize = rmem.offs.trunc();
    let view_end = rmem_offs
        .checked_add(size)
        .ok_or(OpteeSmcReturnCode::EBadAddr)?;
    if view_end > shm_info.len() {
        return Err(OpteeSmcReturnCode::EBadAddr);
    }
    if size == 0 {
        return ShmInfo::new(Box::new([]), 0, 0);
    }
    let start = page_offset
        .checked_add(rmem_offs)
        .ok_or(OpteeSmcReturnCode::EBadAddr)?;
    let end = start
        .checked_add(size)
        .ok_or(OpteeSmcReturnCode::EBadAddr)?;
    let start_page_index = start / PAGE_SIZE;
    let end_page_index = end.div_ceil(PAGE_SIZE);
    if start_page_index >= shm_info.page_addrs.len() || end_page_index > shm_info.page_addrs.len() {
        return Err(OpteeSmcReturnCode::EBadAddr);
    }
    let mut page_addrs = Vec::with_capacity(end_page_index - start_page_index);
    page_addrs.extend_from_slice(&shm_info.page_addrs[start_page_index..end_page_index]);
    ShmInfo::new(page_addrs.into_boxed_slice(), start % PAGE_SIZE, size)
}

#[cfg(test)]
mod tests {
    use super::*;
    use litebox_common_optee::{OpteeMsgAttr, UteeParamsTypes};
    use litebox_platform_linux_userland::LinuxUserland as Platform;
    use zerocopy::IntoBytes;

    /// An unmapped TA address: any read of it faults.
    const UNMAPPED: usize = 0x8;

    fn platform() -> &'static Platform {
        crate::syscalls::tests::shim_builder().build().platform()
    }

    /// Raw `optee_msg_param`: the attribute word, then the 24-byte payload.
    fn wire(attr: OpteeMsgAttrType, payload: [u64; 3]) -> [u64; 4] {
        [attr as u64, payload[0], payload[1], payload[2]]
    }

    fn msg_args(cmd: OpteeMessageCommand, params: &[[u64; 4]]) -> OpteeMsgArgs {
        let header = OpteeMsgArgsHeader {
            cmd: cmd as u32,
            func: 0,
            session: 0,
            cancel_id: 0,
            pad: 0,
            ret: 0,
            ret_origin: 0,
            num_params: u32::try_from(params.len()).unwrap(),
        };
        OpteeMsgArgs::from_header_and_raw_params(&header, params.as_flattened().as_bytes()).unwrap()
    }

    fn to_bytes(msg_args: &OpteeMsgArgs) -> Vec<u8> {
        let mut blob = alloc::vec![0u8; optee_msg_args_total_size(msg_args.num_params)];
        msg_args.serialize(&mut blob).unwrap();
        blob
    }

    /// Mirrors `TaStack::init` for non-NULL memrefs: records a placement where only
    /// memref output/inout params get a buffer, `(memref_address, buffer_size)`.
    fn record_placement(
        request: &mut TaRequestInfo<PAGE_SIZE>,
        params_address: usize,
        memref_address: usize,
    ) {
        let memref_buffers = core::array::from_fn(|i| match request.params[i] {
            UteeParamOwned::MemrefOutput { buffer_size }
            | UteeParamOwned::MemrefInout { buffer_size, .. } => {
                Some((memref_address, buffer_size))
            }
            _ => None,
        });
        request.ta_layout = Some(crate::TaParamLayout {
            params_address,
            memref_buffers,
        });
    }

    #[test]
    fn writeback_ignores_ta_written_types_and_addresses() {
        let platform = platform();
        let meta = u64::read_from_bytes(OpteeMsgAttr::META_VALUE_INPUT.as_bytes()).unwrap();
        let wire_params = [
            [meta, 0x1111, 0x2222, 0],
            // Client identity with login `TEE_LOGIN_PUBLIC`.
            [meta, 0, 0, 0],
            wire(OpteeMsgAttrType::ValueInout, [1, 2, 0x33]),
            wire(OpteeMsgAttrType::TmemOutput, [0x10_0000, 0x40, 0xabc]),
            wire(OpteeMsgAttrType::ValueInput, [4, 5, 6]),
            wire(OpteeMsgAttrType::None, [7, 8, 9]),
        ];
        let original = msg_args(OpteeMessageCommand::OpenSession, &wire_params);
        let mut request = decode_ta_request(platform, &original).unwrap();
        let mut expected_params = wire_params;
        expected_params[2] = wire(OpteeMsgAttrType::ValueInout, [0xa0, 0xb0, 0x33]);
        expected_params[3] = wire(OpteeMsgAttrType::TmemOutput, [0x10_0000, 0, 0xabc]);
        let mut expected = msg_args(OpteeMessageCommand::OpenSession, &expected_params);
        expected.ret = TeeResult::Success;
        expected.ret_origin = TeeOrigin::TrustedApp;
        expected.session = 42;
        // The memref at TA index 1 has TA-written address 0xa1 and size 0. Its
        // zero-length copy is staged, but `ShmInfo::copy_from_user` returns early
        // for it, so shared memory (unmappable in userland) is never touched.
        let mut params = UteeParams {
            vals: [0xa0, 0xb0, 0xa1, 0, 0xa2, 0xb2, 0xa3, 0xb3],
            ..UteeParams::new()
        };

        // All value outputs, all memref outputs, and all invalid.
        for types in [0x2222_u64, 0x6666, 0xffff] {
            params.types = UteeParamsTypes::read_from_bytes(types.as_bytes()).unwrap();
            let params_address = core::ptr::from_ref(&params).expose_provenance();
            record_placement(&mut request, params_address, UNMAPPED);
            let mut msg_args = original;
            update_optee_msg_args(
                platform,
                TeeResult::Success,
                TeeOrigin::TrustedApp,
                Some(42),
                Some(&request),
                &mut msg_args,
            )
            .unwrap_or_else(|e| panic!("types {types:#x}: {e:?}"));
            assert_eq!(to_bytes(&msg_args), to_bytes(&expected), "types {types:#x}");
        }

        // Size 0x10 stages a copy from the recorded buffer, not from 0xa1.
        params.vals[3] = 0x10;
        let params_address = core::ptr::from_ref(&params).expose_provenance();
        record_placement(&mut request, params_address, UNMAPPED);
        let outputs = ParamOutputs::Ta(&request);
        let copies =
            stage_outputs::<Platform>(outputs, TeeResult::Success, &mut { original }).unwrap();
        let copy = copies[1].as_ref().expect("memref output 1 is staged");
        assert_eq!((copy.src, copy.len), (UNMAPPED, 0x10));
        assert!(core::ptr::eq(
            copy.dst,
            request.shm_info[1].as_ref().unwrap()
        ));

        // A recorded buffer smaller than the size is rejected.
        request.ta_layout = Some(crate::TaParamLayout {
            params_address,
            memref_buffers: [None, Some((UNMAPPED, 0xf)), None, None],
        });
        let outputs = ParamOutputs::Ta(&request);
        assert!(matches!(
            stage_outputs::<Platform>(outputs, TeeResult::Success, &mut { original }),
            Err(OpteeSmcReturnCode::EBadAddr)
        ));
    }

    #[test]
    fn target_dead_writes_header_only() {
        let platform = platform();
        let original = msg_args(
            OpteeMessageCommand::InvokeCommand,
            &[
                wire(OpteeMsgAttrType::ValueOutput, [1, 2, 3]),
                wire(OpteeMsgAttrType::TmemOutput, [0x10_0000, 0x40, 0xabc]),
            ],
        );
        let mut request = decode_ta_request(platform, &original).unwrap();
        // Any read of the dead TA's memory fails.
        record_placement(&mut request, UNMAPPED, UNMAPPED);
        let mut expected = original;
        expected.ret = TeeResult::TargetDead;
        expected.ret_origin = TeeOrigin::Tee;

        let mut msg_args = original;
        update_optee_msg_args(
            platform,
            TeeResult::TargetDead,
            TeeOrigin::Tee,
            None,
            Some(&request),
            &mut msg_args,
        )
        .unwrap();
        assert_eq!(to_bytes(&msg_args), to_bytes(&expected));
    }

    /// NULL TMEMs of any size reach the TA as NULL buffers of size 0, unlike a
    /// zero-sized TMEM with a buffer. Their output sizes are returned as is, even
    /// on `Success`, without a TA buffer.
    #[test]
    fn null_tmem() {
        let task = crate::syscalls::tests::init_platform();
        let platform = task.global.platform;
        let original = msg_args(
            OpteeMessageCommand::InvokeCommand,
            &[
                wire(OpteeMsgAttrType::TmemInput, [0, u64::MAX, 0]),
                wire(OpteeMsgAttrType::TmemOutput, [0, u64::MAX, 0]),
                wire(OpteeMsgAttrType::TmemInout, [0, u64::MAX, 0]),
                wire(OpteeMsgAttrType::TmemInput, [PAGE_SIZE as u64, 0, 0]),
            ],
        );
        let mut request = decode_ta_request(platform, &original).unwrap();

        let mut stack = crate::loader::ta_stack::allocate_stack(&task, None).unwrap();
        let layout = stack
            .init(platform, &request.params, &request.shm_info)
            .unwrap();
        let ptr = crate::UserMutPtr::<Platform, UteeParams>::from_usize(layout.params_address);
        let mut params = ptr.read_at_offset(0).unwrap();
        assert!(params.has_types([
            TeeParamType::MemrefInput,
            TeeParamType::MemrefOutput,
            TeeParamType::MemrefInout,
            TeeParamType::MemrefInput,
        ]));
        for index in 0..3 {
            assert_eq!(params.get_values(index), Ok(Some((0, 0))));
        }
        let (address, len) = params.get_values(3).unwrap().unwrap();
        assert_ne!(address, 0, "a zero-sized TMEM with a buffer is not NULL");
        assert_eq!(len, 0);
        assert_eq!(layout.memref_buffers, [None; UteeParams::TEE_NUM_PARAMS]);

        // The TA leaves the output size at 0 and reports an oversized inout size.
        let size = MAX_SHM_MEMREF_SIZE as u64 + 1;
        params.set_values(2, 0, size).unwrap();
        ptr.write_at_offset(0, params).unwrap();
        request.ta_layout = Some(layout);
        let mut msg_args = original;
        update_optee_msg_args(
            platform,
            TeeResult::Success,
            TeeOrigin::TrustedApp,
            None,
            Some(&request),
            &mut msg_args,
        )
        .unwrap();
        assert_eq!(msg_args.get_param_tmem(1).unwrap().size, 0);
        assert_eq!(msg_args.get_param_tmem(2).unwrap().size, size);
    }
}
