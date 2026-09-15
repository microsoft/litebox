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
//! continuation state. [`RpcStage`] records which RPC response is expected,
//! while [`RpcContext`] retains the registered-memory offset, allocation
//! reference, and action to perform after cleanup. Stage-checked transitions
//! prevent a response from being interpreted as a different step of the
//! protocol.
//!
//! Upstream OP-TEE retains the allocated memory object after a successful
//! `rpc_load()` and releases it when the TA store handle closes (or immediately
//! on an error). LiteBox instead copies or caches the loaded binary in trusted
//! memory and tracks the subsequent `SHM_FREE` round trip explicitly with
//! [`RpcStage::ShmFree`].

use alloc::boxed::Box;
use core::sync::atomic::{AtomicU32, Ordering};
use hashbrown::HashMap;
use litebox_common_optee::{OpteeSmcReturnCode, TeeUuid};
use once_cell::race::OnceBox;
use spin::mutex::SpinMutex;

/// Maximum number of RPC contexts that may be active at once.
pub const MAX_RPC_CONTEXTS: usize = 1024;

/// Progress of an RPC-backed Dynamic TA request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RpcStage {
    LoadTaSize,
    ShmAlloc,
    LoadTaBinary,
    ShmFree,
}

/// An RPC context map operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RpcContextError {
    Full,
    AlreadyExists,
    NotFound,
    UnexpectedStage,
}

/// Action to take after an in-flight shared-memory free RPC returns.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum RpcCompletion {
    OpenSession,
    ReturnError(OpteeSmcReturnCode),
}

/// Trusted state for an RPC-backed Dynamic TA request.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RpcContext {
    stage: RpcStage,
    ta_uuid: TeeUuid,
    registered_shm_ref: u64,
    regd_shm_offset: usize,
    requested_size: Option<u64>,
    /// Opaque normal-world allocation reference used for the `SHM_FREE` RPC.
    shm_ref: Option<u64>,
    /// Whether this context owns an entry for the allocation in the local SHM map.
    local_shm_registered: bool,
    completion: RpcCompletion,
}

impl RpcContext {
    fn new(
        stage: RpcStage,
        ta_uuid: TeeUuid,
        registered_shm_ref: u64,
        regd_shm_offset: usize,
    ) -> Self {
        Self {
            stage,
            ta_uuid,
            registered_shm_ref,
            regd_shm_offset,
            requested_size: None,
            shm_ref: None,
            local_shm_registered: false,
            completion: RpcCompletion::OpenSession,
        }
    }

    /// Return the current RPC stage.
    pub fn stage(&self) -> RpcStage {
        self.stage
    }

    /// Return the TA UUID captured when the RPC sequence started.
    pub fn ta_uuid(&self) -> TeeUuid {
        self.ta_uuid
    }

    /// Return the registered shared-memory reference containing the RPC arguments.
    pub fn registered_shm_ref(&self) -> u64 {
        self.registered_shm_ref
    }

    /// Return the offset of the message arguments in registered shared memory.
    pub fn registered_shm_offset(&self) -> usize {
        self.regd_shm_offset
    }

    /// Return the shared-memory reference associated with this context.
    pub fn shm_ref(&self) -> Option<u64> {
        self.shm_ref
    }

    /// Return whether this context inserted its allocation into the local SHM map.
    pub fn local_shm_registered(&self) -> bool {
        self.local_shm_registered
    }

    /// Return the action to perform when this RPC sequence finishes.
    pub fn completion(&self) -> RpcCompletion {
        self.completion
    }
}

/// Maps RPC context IDs to trusted continuation state.
pub struct RpcContextMap {
    next_id: AtomicU32,
    inner: SpinMutex<HashMap<u32, RpcContext>>,
    max_contexts: usize,
}

impl RpcContextMap {
    /// Create an empty RPC context map.
    pub fn new() -> Self {
        Self::with_limits(0, MAX_RPC_CONTEXTS)
    }

    fn with_limits(next_id: u32, max_contexts: usize) -> Self {
        Self {
            next_id: AtomicU32::new(next_id),
            inner: SpinMutex::new(HashMap::new()),
            max_contexts,
        }
    }

    /// Allocate a unique context ID and associate it with trusted continuation state.
    pub fn allocate(
        &self,
        stage: RpcStage,
        ta_uuid: TeeUuid,
        registered_shm_ref: u64,
        regd_shm_offset: usize,
    ) -> Result<u32, RpcContextError> {
        let mut contexts = self.inner.lock();
        if contexts.len() >= self.max_contexts {
            return Err(RpcContextError::Full);
        }

        // With N active entries, at least one of N + 1 consecutive IDs is free.
        for _ in 0..=contexts.len() {
            let context_id = self.next_id.fetch_add(1, Ordering::Relaxed);
            if let hashbrown::hash_map::Entry::Vacant(entry) = contexts.entry(context_id) {
                entry.insert(RpcContext::new(
                    stage,
                    ta_uuid,
                    registered_shm_ref,
                    regd_shm_offset,
                ));
                return Ok(context_id);
            }
        }

        Err(RpcContextError::Full)
    }

    /// Insert a context with a caller-provided ID.
    #[cfg(test)]
    fn insert(
        &self,
        context_id: u32,
        stage: RpcStage,
        ta_uuid: TeeUuid,
        registered_shm_ref: u64,
        regd_shm_offset: usize,
    ) -> Result<(), RpcContextError> {
        let mut contexts = self.inner.lock();
        if contexts.contains_key(&context_id) {
            return Err(RpcContextError::AlreadyExists);
        }
        if contexts.len() >= self.max_contexts {
            return Err(RpcContextError::Full);
        }
        contexts.insert(
            context_id,
            RpcContext::new(stage, ta_uuid, registered_shm_ref, regd_shm_offset),
        );
        Ok(())
    }

    /// Get the current stage for `context_id`.
    pub fn get_curr_stage(&self, context_id: u32) -> Option<RpcStage> {
        self.inner.lock().get(&context_id).map(RpcContext::stage)
    }

    /// Get the registered-SHM offset captured before `args[3]` became the context ID.
    pub fn get_regd_shm_offset(&self, context_id: u32) -> Option<usize> {
        self.inner
            .lock()
            .get(&context_id)
            .map(|context| context.regd_shm_offset)
    }

    /// Get the TA UUID captured when `context_id` was allocated.
    pub fn get_ta_uuid(&self, context_id: u32) -> Option<TeeUuid> {
        self.inner.lock().get(&context_id).map(RpcContext::ta_uuid)
    }

    /// Get the registered shared-memory reference containing the RPC arguments.
    pub fn get_registered_shm_ref(&self, context_id: u32) -> Option<u64> {
        self.inner
            .lock()
            .get(&context_id)
            .map(RpcContext::registered_shm_ref)
    }

    /// Record the requested allocation size associated with `context_id`.
    pub fn set_requested_size(
        &self,
        context_id: u32,
        expected_stage: RpcStage,
        requested_size: u64,
    ) -> Result<(), RpcContextError> {
        let mut contexts = self.inner.lock();
        let context = contexts
            .get_mut(&context_id)
            .ok_or(RpcContextError::NotFound)?;
        if context.stage != expected_stage {
            return Err(RpcContextError::UnexpectedStage);
        }
        context.requested_size = Some(requested_size);
        Ok(())
    }

    /// Get the trusted allocation size requested for `context_id`.
    pub fn get_requested_size(&self, context_id: u32) -> Option<u64> {
        self.inner
            .lock()
            .get(&context_id)
            .and_then(|context| context.requested_size)
    }

    /// Record the shared-memory allocation associated with `context_id`.
    pub fn set_shm_ref(
        &self,
        context_id: u32,
        expected_stage: RpcStage,
        shm_ref: u64,
    ) -> Result<(), RpcContextError> {
        let mut contexts = self.inner.lock();
        let context = contexts
            .get_mut(&context_id)
            .ok_or(RpcContextError::NotFound)?;
        if context.stage != expected_stage {
            return Err(RpcContextError::UnexpectedStage);
        }
        context.shm_ref = Some(shm_ref);
        Ok(())
    }

    /// Get the trusted shared-memory reference for `context_id`.
    pub fn get_shm_ref(&self, context_id: u32) -> Option<u64> {
        self.inner
            .lock()
            .get(&context_id)
            .and_then(RpcContext::shm_ref)
    }

    /// Record that this context inserted its allocation into the local SHM map.
    pub fn set_local_shm_registered(
        &self,
        context_id: u32,
        expected_stage: RpcStage,
    ) -> Result<(), RpcContextError> {
        let mut contexts = self.inner.lock();
        let context = contexts
            .get_mut(&context_id)
            .ok_or(RpcContextError::NotFound)?;
        if context.stage != expected_stage {
            return Err(RpcContextError::UnexpectedStage);
        }
        context.local_shm_registered = true;
        Ok(())
    }

    /// Return whether `context_id` owns an entry in the local SHM map.
    pub fn is_local_shm_registered(&self, context_id: u32) -> Option<bool> {
        self.inner
            .lock()
            .get(&context_id)
            .map(RpcContext::local_shm_registered)
    }

    /// Set the action to perform after the current RPC sequence is cleaned up.
    pub fn set_completion(
        &self,
        context_id: u32,
        expected_stage: RpcStage,
        completion: RpcCompletion,
    ) -> Result<(), RpcContextError> {
        let mut contexts = self.inner.lock();
        let context = contexts
            .get_mut(&context_id)
            .ok_or(RpcContextError::NotFound)?;
        if context.stage != expected_stage {
            return Err(RpcContextError::UnexpectedStage);
        }
        context.completion = completion;
        Ok(())
    }

    /// Atomically advance the stage of a context from `expected` to `next` if it matches the current stage.
    /// TODO: Check if the new stage is a valid transition from the current stage.
    pub fn transition(
        &self,
        context_id: u32,
        expected: RpcStage,
        next: RpcStage,
    ) -> Result<(), RpcContextError> {
        let mut contexts = self.inner.lock();
        let context = contexts
            .get_mut(&context_id)
            .ok_or(RpcContextError::NotFound)?;
        if context.stage != expected {
            return Err(RpcContextError::UnexpectedStage);
        }
        context.stage = next;
        Ok(())
    }

    /// Remove and return a context.
    pub fn take(&self, context_id: u32) -> Option<RpcContext> {
        self.inner.lock().remove(&context_id)
    }

    /// Return the number of active RPC contexts.
    pub fn len(&self) -> usize {
        self.inner.lock().len()
    }

    /// Return whether there are no active RPC contexts.
    pub fn is_empty(&self) -> bool {
        self.inner.lock().is_empty()
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
    fn allocates_unique_context_ids() {
        let contexts = RpcContextMap::new();
        let first = contexts
            .allocate(RpcStage::LoadTaSize, test_uuid(1), 0x10, 0x100)
            .unwrap();
        let second = contexts
            .allocate(RpcStage::LoadTaSize, test_uuid(2), 0x20, 0x200)
            .unwrap();

        assert_ne!(first, second);
        assert_eq!(contexts.len(), 2);
        assert_eq!(contexts.get_regd_shm_offset(first), Some(0x100));
        assert_eq!(contexts.get_regd_shm_offset(second), Some(0x200));
        assert_eq!(contexts.get_registered_shm_ref(first), Some(0x10));
        assert_eq!(contexts.get_registered_shm_ref(second), Some(0x20));
        assert_eq!(contexts.get_ta_uuid(first), Some(test_uuid(1)));
        assert_eq!(contexts.get_ta_uuid(second), Some(test_uuid(2)));
    }

    #[test]
    fn transitions_a_stable_context_id() {
        let contexts = RpcContextMap::new();
        let context_id = contexts
            .allocate(RpcStage::LoadTaSize, test_uuid(1), 1, 0)
            .unwrap();

        assert_eq!(
            contexts.transition(context_id, RpcStage::LoadTaSize, RpcStage::ShmAlloc),
            Ok(())
        );
        assert_eq!(
            contexts.get_curr_stage(context_id),
            Some(RpcStage::ShmAlloc)
        );
        assert_eq!(
            contexts.transition(context_id, RpcStage::LoadTaSize, RpcStage::LoadTaBinary),
            Err(RpcContextError::UnexpectedStage)
        );
    }

    #[test]
    fn taking_a_context_rejects_replay() {
        let contexts = RpcContextMap::new();
        let context_id = contexts
            .allocate(RpcStage::ShmFree, test_uuid(1), 1, 0)
            .unwrap();

        assert_eq!(
            contexts.take(context_id).map(|context| context.stage()),
            Some(RpcStage::ShmFree)
        );
        assert_eq!(contexts.take(context_id), None);
        assert!(contexts.is_empty());
    }

    #[test]
    fn tracks_shm_ref_in_trusted_context() {
        let contexts = RpcContextMap::new();
        let context_id = contexts
            .allocate(RpcStage::ShmAlloc, test_uuid(1), 1, 0)
            .unwrap();

        assert_eq!(
            contexts.set_shm_ref(context_id, RpcStage::ShmAlloc, 0x1234),
            Ok(())
        );
        assert_eq!(contexts.get_shm_ref(context_id), Some(0x1234));
        assert_eq!(
            contexts.set_shm_ref(context_id, RpcStage::LoadTaBinary, 0x5678),
            Err(RpcContextError::UnexpectedStage)
        );
        assert_eq!(contexts.get_shm_ref(context_id), Some(0x1234));
    }

    #[test]
    fn tracks_requested_size_in_trusted_context() {
        let contexts = RpcContextMap::new();
        let context_id = contexts
            .allocate(RpcStage::LoadTaSize, test_uuid(1), 1, 0)
            .unwrap();

        assert_eq!(
            contexts.set_requested_size(context_id, RpcStage::LoadTaSize, 0x4000),
            Ok(())
        );
        assert_eq!(contexts.get_requested_size(context_id), Some(0x4000));
        assert_eq!(
            contexts.set_requested_size(context_id, RpcStage::ShmAlloc, 0x8000),
            Err(RpcContextError::UnexpectedStage)
        );
        assert_eq!(contexts.get_requested_size(context_id), Some(0x4000));
    }

    #[test]
    fn tracks_local_shm_registration_ownership() {
        let contexts = RpcContextMap::new();
        let context_id = contexts
            .allocate(RpcStage::ShmAlloc, test_uuid(1), 1, 0)
            .unwrap();

        assert_eq!(contexts.is_local_shm_registered(context_id), Some(false));
        assert_eq!(
            contexts.set_local_shm_registered(context_id, RpcStage::ShmAlloc),
            Ok(())
        );
        assert_eq!(contexts.is_local_shm_registered(context_id), Some(true));
        assert_eq!(
            contexts.set_local_shm_registered(context_id, RpcStage::LoadTaBinary),
            Err(RpcContextError::UnexpectedStage)
        );
    }

    #[test]
    fn tracks_post_free_completion() {
        let contexts = RpcContextMap::new();
        let context_id = contexts
            .allocate(RpcStage::LoadTaBinary, test_uuid(1), 1, 0)
            .unwrap();

        contexts
            .set_completion(
                context_id,
                RpcStage::LoadTaBinary,
                RpcCompletion::ReturnError(OpteeSmcReturnCode::EBadCmd),
            )
            .unwrap();
        assert_eq!(
            contexts.take(context_id).unwrap().completion(),
            RpcCompletion::ReturnError(OpteeSmcReturnCode::EBadCmd)
        );
    }

    #[test]
    fn enforces_capacity_and_duplicate_ids() {
        let contexts = RpcContextMap::with_limits(0, 1);
        assert_eq!(
            contexts.insert(7, RpcStage::LoadTaSize, test_uuid(1), 1, 0),
            Ok(())
        );
        assert_eq!(
            contexts.insert(7, RpcStage::ShmAlloc, test_uuid(1), 1, 0),
            Err(RpcContextError::AlreadyExists)
        );
        assert_eq!(
            contexts.allocate(RpcStage::LoadTaSize, test_uuid(1), 1, 0),
            Err(RpcContextError::Full)
        );
    }

    #[test]
    fn allocation_wraps_and_skips_active_ids() {
        let contexts = RpcContextMap::with_limits(u32::MAX, 3);
        contexts
            .insert(u32::MAX, RpcStage::LoadTaSize, test_uuid(1), 1, 0)
            .unwrap();

        let context_id = contexts
            .allocate(RpcStage::ShmAlloc, test_uuid(2), 2, 0)
            .unwrap();
        assert_eq!(context_id, 0);
        assert_eq!(
            contexts.get_curr_stage(u32::MAX),
            Some(RpcStage::LoadTaSize)
        );
        assert_eq!(contexts.get_curr_stage(0), Some(RpcStage::ShmAlloc));
    }
}
