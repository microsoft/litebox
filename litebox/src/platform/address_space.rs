// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Address-space management types and traits for multi-process support.
//!
//! The [`AddressSpaceProvider`] trait is an **optional** South interface that
//! platforms implement to manage per-process address spaces. On kernel platforms
//! (e.g., LVBS) each process gets its own page table; on userland platforms the
//! single host address space is partitioned into non-overlapping VA sub-ranges.
//!
//! See the multi-process design document at
//! `docs/multi-process-single-address-space.md` §4 for the full
//! rationale.

use core::ops::Range;
use thiserror::Error;

/// The result of forking an address space.
///
/// The variant tells the caller what kind of copy was created so it can adjust
/// its behavior (e.g., whether to copy page contents or share them).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForkedAddressSpace<Id> {
    /// Kernel platforms: independent copy-on-write copy with the full address
    /// range. The child has its own page tables; CoW faults are resolved by
    /// the platform.
    Independent(Id),
    /// Userland platforms: a new VA-range partition is assigned to the child.
    /// Parent memory is shared (vfork-style semantics); the shim is
    /// responsible for copying pages as needed.
    SharedWithParent(Id),
}

/// Errors that can occur during address-space operations.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum AddressSpaceError {
    /// No free address-space slots or VA ranges available.
    #[error("no address space slots available")]
    NoSpace,
    /// The given address-space ID is not valid (already destroyed, never
    /// created, etc.).
    #[error("invalid address space id")]
    InvalidId,
    /// The platform does not support this operation.
    #[error("operation not supported by this platform")]
    NotSupported,
}

/// A provider for managing per-process address spaces.
///
/// This is an **optional** trait — platforms that do not yet support
/// multi-process may leave all methods at the default (which returns
/// [`AddressSpaceError::NotSupported`]).
///
/// # Associated Type
///
/// `AddressSpaceId` is an opaque, lightweight handle that identifies one
/// address space. It must be `Copy + Eq + Send + Sync` so it can be stored
/// inside `ProcessContext` and passed across threads.
pub trait AddressSpaceProvider {
    /// Opaque identifier for an address space.
    type AddressSpaceId: Copy + Eq + Send + Sync + core::fmt::Debug;

    /// Create a new, empty address space.
    ///
    /// * Kernel platforms: allocate a top-level page table (e.g., PML4) and
    ///   copy kernel entries.
    /// * Userland platforms: claim a free VA-range partition.
    fn create_address_space(&self) -> Result<Self::AddressSpaceId, AddressSpaceError> {
        Err(AddressSpaceError::NotSupported)
    }

    /// Destroy an address space, releasing all associated resources.
    ///
    /// After this call, `id` is invalid and must not be reused.
    fn destroy_address_space(&self, id: Self::AddressSpaceId) -> Result<(), AddressSpaceError> {
        let _ = id;
        Err(AddressSpaceError::NotSupported)
    }

    /// Fork an address space from `parent`.
    ///
    /// Returns a [`ForkedAddressSpace`] indicating what kind of fork was
    /// performed:
    ///
    /// * [`Independent`](ForkedAddressSpace::Independent) — kernel: full CoW
    ///   copy.
    /// * [`SharedWithParent`](ForkedAddressSpace::SharedWithParent) — userland:
    ///   new VA partition, parent pages shared.
    fn fork_address_space(
        &self,
        parent: Self::AddressSpaceId,
    ) -> Result<ForkedAddressSpace<Self::AddressSpaceId>, AddressSpaceError> {
        let _ = parent;
        Err(AddressSpaceError::NotSupported)
    }

    /// Make `id` the active address space for the current CPU / thread.
    ///
    /// * Kernel: switch CR3 (or equivalent).
    /// * Userland: typically a no-op.
    fn activate_address_space(&self, id: Self::AddressSpaceId) -> Result<(), AddressSpaceError> {
        let _ = id;
        Err(AddressSpaceError::NotSupported)
    }

    /// Execute `f` with the given address space active, then restore the
    /// previously active address space.
    ///
    /// On kernel platforms implementations **must** restore the prior address
    /// space even if `f` panics (use a guard / RAII pattern). Userland
    /// platforms may keep this as a thin wrapper.
    fn with_address_space<R>(
        &self,
        id: Self::AddressSpaceId,
        f: impl FnOnce() -> R,
    ) -> Result<R, AddressSpaceError> {
        self.activate_address_space(id)?;
        let result = f();
        Ok(result)
    }

    /// Whether the platform requires eager copy-on-write snapshots during
    /// vfork instead of lazy page-fault-driven CoW.
    ///
    /// When `true`, the shim eagerly copies all writable guest pages before
    /// spawning the vfork child and restores them after the child execs or
    /// exits. When `false` (the default), the shim marks writable pages
    /// read-only and lazily snapshots individual pages on first write fault.
    ///
    /// Platforms where the exception/fault handler shares the guest address
    /// space (e.g., Windows userland) must set this to `true` because a
    /// CoW fault inside the handler itself would be fatal.
    const EAGER_COW_FOR_VFORK: bool = false;

    /// Return the VA range available to the given address space.
    ///
    /// * Kernel: the full `TASK_ADDR_MIN..TASK_ADDR_MAX`.
    /// * Userland: the sub-range partition assigned to this address space.
    fn address_space_range(
        &self,
        id: Self::AddressSpaceId,
    ) -> Result<Range<usize>, AddressSpaceError> {
        let _ = id;
        Err(AddressSpaceError::NotSupported)
    }
}
