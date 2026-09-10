// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! RPC context tracking for multi-call OP-TEE operations.
//!
//! # Dynamic TA loading
//!
//! OP-TEE loads a Dynamic TA from the normal world with a sequence of RPCs.
//! The reference flow is implemented by `rpc_load()` in
//! `optee_os/core/kernel/ree_fs_ta.c`; the RPC transport and shared-memory
//! allocation are implemented by `thread_rpc_cmd()` and
//! `thread_rpc_alloc_payload()` in
//! `optee_os/core/arch/arm/kernel/thread_optee_smc.c`.
//!
//! LiteBox follows the same high-level protocol across the VTL boundary:
//!
//! ```text
//! VTL1 (LiteBox OP-TEE shim)                 VTL0 (driver / supplicant)
//!              |                                         |
//!              |-- LOAD_TA(UUID, empty output TMEM) ---->|
//!              |<------- TA size in TMEM.size -----------|
//!              |                                         |
//!              |-- SHM_ALLOC(application, size, align) ->|
//!              |<-- TMEM { buf_ptr, size, shm_ref } -----|
//!              |                                         |
//!              |  Register the allocation by shm_ref     |
//!              |                                         |
//!              |-- LOAD_TA(UUID, output RMEM) ---------->|
//!              |<------ TA binary written to RMEM -------|
//!              |                                         |
//!              |  Read, validate, and copy the TA        |
//!              |                                         |
//!              |-- SHM_FREE(application, shm_ref) ------>|
//!              |<-------------- completion --------------|
//! ```
//!
//! The first `LOAD_TA` discovers the required binary size. `SHM_ALLOC` then
//! returns a temporary-memory reference containing the physical buffer address,
//! allocated size, and an opaque shared-memory reference. LiteBox records that
//! allocation and sends the second `LOAD_TA` as an RMEM referring to the same
//! `shm_ref`; the normal-world driver resolves it before asking the supplicant
//! to fill the buffer with the TA binary.
//!
//! # Why explicit contexts are needed
//!
//! OP-TEE OS executes this sequence on a secure-world thread. `thread_rpc()`
//! suspends that thread while normal world handles an RPC, preserving the
//! `rpc_load()` call stack, local variables, RPC arguments, and memory-object
//! references. Normal world returns the thread ID in register `a3`, allowing
//! `OPTEE_SMC_CALL_RETURN_FROM_RPC` to resume the suspended continuation. The
//! Dynamic TA stage is therefore implicit in the saved thread execution state;
//! OP-TEE does not need a separate protocol-stage enum.
//!
//! LiteBox has no equivalent resumable OP-TEE thread and call stack. Instead,
//! [`RpcContextMap`] associates the context ID carried in `args[3]` with trusted
//! continuation state. [`RpcContext`] records which RPC response is expected
//! and carries only the state valid for that stage. Stage-checked transitions
//! prevent a response from being interpreted as a different step of the
//! protocol.
//!
//! LiteBox copies the loaded binary into trusted memory, then releases the VTL0
//! allocation with a `SHM_FREE` RPC tracked by [`RpcContext::ShmFree`]. The
//! trusted cached binary is dropped after ldelf loads it into TA runtime memory.

use alloc::{boxed::Box, sync::Arc};
use hashbrown::HashMap;
use litebox::utils::id_pool::IdPool;
use litebox_common_optee::{OpteeSmcReturnCode, TeeUuid};
use once_cell::race::OnceBox;
use spin::mutex::SpinMutex;

const MAX_RPC_CONTEXTS: u32 = 1024;

/// An RPC context map operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RpcContextError {
    Full,
    UnexpectedStage,
}

/// Action to take after an in-flight shared-memory free RPC returns.
#[derive(Clone, Debug, PartialEq)]
pub enum RpcCompletion {
    OpenSession { ta_binary: Arc<[u8]> },
    ReturnError(OpteeSmcReturnCode),
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RpcCommon {
    pub ta_uuid: TeeUuid,
    // RPC continuation reuses args[3] for the context ID. Use these fields to
    // preserve the original registered SHM reference and offset
    // before overwriting it.
    pub registered_shm_ref: u64,
    pub regd_shm_offset: usize,
}

/// Continuation state for an RPC-backed Dynamic TA request.
#[derive(Clone, Debug, PartialEq)]
pub enum RpcContext {
    LoadTaSize {
        common: RpcCommon,
    },
    ShmAlloc {
        common: RpcCommon,
        requested_size: u64,
    },
    LoadTaBinary {
        common: RpcCommon,
        requested_size: u64,
        shm_ref: u64,
    },
    ShmFree {
        common: RpcCommon,
        shm_ref: u64,
        completion: RpcCompletion,
    },
}

impl RpcContext {
    fn new(ta_uuid: TeeUuid, registered_shm_ref: u64, regd_shm_offset: usize) -> Self {
        Self::LoadTaSize {
            common: RpcCommon {
                ta_uuid,
                registered_shm_ref,
                regd_shm_offset,
            },
        }
    }
}

struct RpcContexts {
    ids: IdPool,
    contexts: HashMap<u32, RpcContext>,
}

/// Maps RPC context IDs to continuation state.
pub struct RpcContextMap {
    inner: SpinMutex<RpcContexts>,
}

impl RpcContextMap {
    pub fn new() -> Self {
        Self::with_capacity(MAX_RPC_CONTEXTS)
    }

    fn with_capacity(capacity: u32) -> Self {
        Self {
            inner: SpinMutex::new(RpcContexts {
                ids: IdPool::with_capacity(capacity),
                contexts: HashMap::new(),
            }),
        }
    }

    /// Allocate a context for the first `LOAD_TA` response.
    pub fn allocate(
        &self,
        ta_uuid: TeeUuid,
        registered_shm_ref: u64,
        regd_shm_offset: usize,
    ) -> Result<u32, RpcContextError> {
        let mut inner = self.inner.lock();
        let context_id = inner.ids.allocate().ok_or(RpcContextError::Full)?;
        inner.contexts.insert(
            context_id,
            RpcContext::new(ta_uuid, registered_shm_ref, regd_shm_offset),
        );
        Ok(context_id)
    }

    /// Remove a context from the map while keeping its ID reserved.
    pub fn take(&self, context_id: u32) -> Option<RpcContext> {
        self.inner.lock().contexts.remove(&context_id)
    }

    /// Reinsert a context before returning for another RPC or retryable result.
    pub fn insert(&self, context_id: u32, context: RpcContext) -> Result<(), RpcContextError> {
        let mut inner = self.inner.lock();
        if inner.contexts.contains_key(&context_id) {
            return Err(RpcContextError::UnexpectedStage);
        }
        inner.contexts.insert(context_id, context);
        Ok(())
    }

    /// Recycle a context ID after its RPC sequence finishes.
    pub fn release(&self, context_id: u32) {
        let mut inner = self.inner.lock();
        debug_assert!(!inner.contexts.contains_key(&context_id));
        inner.ids.recycle(context_id);
    }
}

impl Default for RpcContextMap {
    fn default() -> Self {
        Self::new()
    }
}

/// Return the global RPC context map.
pub fn rpc_context_map() -> &'static RpcContextMap {
    static RPC_CONTEXT_MAP: OnceBox<RpcContextMap> = OnceBox::new();
    RPC_CONTEXT_MAP.get_or_init(|| Box::new(RpcContextMap::new()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_uuid(value: u32) -> TeeUuid {
        TeeUuid {
            time_low: value,
            time_mid: 0,
            time_hi_and_version: 0,
            clock_seq_and_node: [0; 8],
        }
    }

    #[test]
    fn taken_context_keeps_its_id_reserved() {
        let contexts = RpcContextMap::with_capacity(1);
        let first_id = contexts.allocate(test_uuid(1), 1, 0).unwrap();
        let first = contexts.take(first_id).unwrap();

        assert_eq!(
            contexts.allocate(test_uuid(2), 2, 0),
            Err(RpcContextError::Full)
        );

        contexts.insert(first_id, first.clone()).unwrap();

        assert_eq!(contexts.take(first_id), Some(first));
        contexts.release(first_id);
        assert_eq!(contexts.allocate(test_uuid(3), 3, 0).unwrap(), first_id);
    }
}
