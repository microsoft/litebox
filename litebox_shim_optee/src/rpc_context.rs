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
//!              |<------- TA size in TMEM.size ------------|
//!              |                                         |
//!              |-- SHM_ALLOC(application, size, align) -->|
//!              |<-- TMEM { buf_ptr, size, shm_ref } ------|
//!              |                                         |
//!              |  Register the allocation by shm_ref     |
//!              |                                         |
//!              |-- LOAD_TA(UUID, output RMEM) ------------>|
//!              |<------ TA binary written to RMEM ---------|
//!              |                                         |
//!              |  Read, validate, and copy the TA        |
//!              |                                         |
//!              |-- SHM_FREE(application, shm_ref) ------->|
//!              |<-------------- completion ---------------|
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

use alloc::boxed::Box;
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
    NotFound,
    UnexpectedStage,
}

/// Action to take after an in-flight shared-memory free RPC returns.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum RpcCompletion {
    OpenSession,
    ReturnError(OpteeSmcReturnCode),
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RpcCommon {
    ta_uuid: TeeUuid,
    // RPC continuation reuses args[3] for the context ID. Use these fields to
    // preserve the original registered SHM reference and offset
    // before overwriting it.
    registered_shm_ref: u64,
    regd_shm_offset: usize,
}

/// Trusted continuation state for an RPC-backed Dynamic TA request.
#[derive(Clone, Copy, Debug, PartialEq)]
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

    fn common(&self) -> RpcCommon {
        match self {
            Self::LoadTaSize { common }
            | Self::ShmAlloc { common, .. }
            | Self::LoadTaBinary { common, .. }
            | Self::ShmFree { common, .. } => *common,
        }
    }

    pub fn ta_uuid(&self) -> TeeUuid {
        self.common().ta_uuid
    }

    pub fn registered_shm_ref(&self) -> u64 {
        self.common().registered_shm_ref
    }

    pub fn registered_shm_offset(&self) -> usize {
        self.common().regd_shm_offset
    }

    pub fn requested_size(&self) -> Option<u64> {
        match self {
            Self::ShmAlloc { requested_size, .. } | Self::LoadTaBinary { requested_size, .. } => {
                Some(*requested_size)
            }
            Self::LoadTaSize { .. } | Self::ShmFree { .. } => None,
        }
    }

    pub fn shm_ref(&self) -> Option<u64> {
        match self {
            Self::LoadTaBinary { shm_ref, .. } | Self::ShmFree { shm_ref, .. } => Some(*shm_ref),
            Self::LoadTaSize { .. } | Self::ShmAlloc { .. } => None,
        }
    }

    pub fn completion(&self) -> Option<RpcCompletion> {
        match self {
            Self::ShmFree { completion, .. } => Some(*completion),
            Self::LoadTaSize { .. } | Self::ShmAlloc { .. } | Self::LoadTaBinary { .. } => None,
        }
    }

    fn into_shm_alloc(self, requested_size: u64) -> Result<Self, RpcContextError> {
        match self {
            Self::LoadTaSize { common } => Ok(Self::ShmAlloc {
                common,
                requested_size,
            }),
            _ => Err(RpcContextError::UnexpectedStage),
        }
    }

    fn into_load_ta_binary(self, shm_ref: u64) -> Result<Self, RpcContextError> {
        match self {
            Self::ShmAlloc {
                common,
                requested_size,
            } => Ok(Self::LoadTaBinary {
                common,
                requested_size,
                shm_ref,
            }),
            _ => Err(RpcContextError::UnexpectedStage),
        }
    }

    fn into_shm_free(
        self,
        shm_ref: u64,
        completion: RpcCompletion,
    ) -> Result<Self, RpcContextError> {
        match self {
            Self::ShmAlloc { common, .. } => Ok(Self::ShmFree {
                common,
                shm_ref,
                completion,
            }),
            Self::LoadTaBinary {
                common,
                shm_ref: expected_shm_ref,
                ..
            } if shm_ref == expected_shm_ref => Ok(Self::ShmFree {
                common,
                shm_ref,
                completion,
            }),
            _ => Err(RpcContextError::UnexpectedStage),
        }
    }
}

struct RpcContexts {
    ids: IdPool,
    contexts: HashMap<u32, RpcContext>,
}

impl RpcContexts {
    fn new() -> Self {
        Self {
            ids: IdPool::with_capacity(MAX_RPC_CONTEXTS),
            contexts: HashMap::new(),
        }
    }
}

/// Maps RPC context IDs to trusted continuation state.
pub struct RpcContextMap {
    inner: SpinMutex<RpcContexts>,
}

impl RpcContextMap {
    /// Create an empty RPC context map.
    pub fn new() -> Self {
        Self {
            inner: SpinMutex::new(RpcContexts::new()),
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

    /// Return a snapshot of a context.
    pub fn get(&self, context_id: u32) -> Option<RpcContext> {
        self.inner.lock().contexts.get(&context_id).copied()
    }

    pub fn transition_to_shm_alloc(
        &self,
        context_id: u32,
        requested_size: u64,
    ) -> Result<(), RpcContextError> {
        self.update(context_id, |context| context.into_shm_alloc(requested_size))
    }

    pub fn transition_to_load_ta_binary(
        &self,
        context_id: u32,
        shm_ref: u64,
    ) -> Result<(), RpcContextError> {
        self.update(context_id, |context| context.into_load_ta_binary(shm_ref))
    }

    pub fn transition_to_shm_free(
        &self,
        context_id: u32,
        shm_ref: u64,
        completion: RpcCompletion,
    ) -> Result<(), RpcContextError> {
        self.update(context_id, |context| {
            context.into_shm_free(shm_ref, completion)
        })
    }

    fn update(
        &self,
        context_id: u32,
        transition: impl FnOnce(RpcContext) -> Result<RpcContext, RpcContextError>,
    ) -> Result<(), RpcContextError> {
        let mut inner = self.inner.lock();
        let context = inner
            .contexts
            .get(&context_id)
            .copied()
            .ok_or(RpcContextError::NotFound)?;
        inner.contexts.insert(context_id, transition(context)?);
        Ok(())
    }

    /// Remove a context and recycle its ID.
    pub fn take(&self, context_id: u32) -> Option<RpcContext> {
        let mut inner = self.inner.lock();
        let context = inner.contexts.remove(&context_id)?;
        inner.ids.recycle(context_id);
        Some(context)
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
    fn tracks_dynamic_ta_rpc_lifecycle() {
        let contexts = RpcContextMap::new();
        let context_id = contexts.allocate(test_uuid(1), 0x10, 0x100).unwrap();

        let initial = contexts.get(context_id).unwrap();
        assert!(matches!(initial, RpcContext::LoadTaSize { .. }));
        assert_eq!(initial.ta_uuid(), test_uuid(1));
        assert_eq!(initial.registered_shm_ref(), 0x10);
        assert_eq!(initial.registered_shm_offset(), 0x100);

        contexts
            .transition_to_shm_alloc(context_id, 0x4000)
            .unwrap();
        assert!(matches!(
            contexts.get(context_id),
            Some(RpcContext::ShmAlloc {
                requested_size: 0x4000,
                ..
            })
        ));

        contexts
            .transition_to_load_ta_binary(context_id, 0x1234)
            .unwrap();
        assert!(matches!(
            contexts.get(context_id),
            Some(RpcContext::LoadTaBinary {
                requested_size: 0x4000,
                shm_ref: 0x1234,
                ..
            })
        ));

        let completion = RpcCompletion::ReturnError(OpteeSmcReturnCode::EBadCmd);
        contexts
            .transition_to_shm_free(context_id, 0x1234, completion)
            .unwrap();
        assert_eq!(
            contexts.take(context_id),
            Some(RpcContext::ShmFree {
                common: initial.common(),
                shm_ref: 0x1234,
                completion,
            })
        );
    }

    #[test]
    fn rejects_incomplete_and_replayed_transitions() {
        let contexts = RpcContextMap::new();
        let context_id = contexts.allocate(test_uuid(1), 1, 0).unwrap();

        contexts.transition_to_shm_alloc(context_id, 1).unwrap();
        assert_eq!(
            contexts.transition_to_shm_alloc(context_id, 2),
            Err(RpcContextError::UnexpectedStage)
        );
        contexts
            .transition_to_load_ta_binary(context_id, 1)
            .unwrap();
        assert_eq!(
            contexts.transition_to_load_ta_binary(context_id, 2),
            Err(RpcContextError::UnexpectedStage)
        );
        assert_eq!(
            contexts.transition_to_shm_free(
                context_id,
                2,
                RpcCompletion::ReturnError(OpteeSmcReturnCode::EBadCmd),
            ),
            Err(RpcContextError::UnexpectedStage)
        );
        assert!(contexts.take(context_id).is_some());
        assert_eq!(contexts.take(context_id), None);
    }
}
