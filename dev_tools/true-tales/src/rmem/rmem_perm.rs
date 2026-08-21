// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Rust slice permissions for the machine model.
//!
//! Registers carry a copyable
//! [`ErasedPPtr`](crate::helpers::erased_pptr::ErasedPPtr) handle plus an
//! offset, while the lifetime-bearing permission lives in the standalone
//! [`RmemStack`](crate::rmem::rmem_stack::RmemStack).
use crate::helpers::erased_pptr::*;
use vstd::prelude::*;

verus! {

/// A held Rust-slice capability permission.
///
/// Stack layers hold either a mutable or shared permission. `Mut` is readable
/// and writable; `Shared` is read-only.
pub tracked enum RmemPerm<'a> {
    /// A mutable (read/write) slice capability.
    Mut(PointsTo<&'a mut [u8]>),
    /// A shared (read-only) slice capability.
    Shared(PointsTo<&'a [u8]>),
}

impl<'a> RmemPerm<'a> {
    /// The capability address of the held permission.
    pub open spec fn addr(self) -> usize {
        match self {
            RmemPerm::Mut(perm) => perm.ptr().addr(),
            RmemPerm::Shared(perm) => perm.ptr().addr(),
        }
    }

    /// Whether the permission matches the type-erased cell carried by a register.
    pub open spec fn matches_pptr(self, cell: ErasedPPtr) -> bool {
        match self {
            RmemPerm::Mut(perm) => perm.ptr() == cell.ptr() as *mut &'a mut [u8],
            RmemPerm::Shared(perm) => perm.ptr() == cell.ptr() as *mut &'a [u8],
        }
    }

    /// Whether the held permission points to initialized memory.
    pub open spec fn is_init(self) -> bool {
        match self {
            RmemPerm::Mut(perm) => perm.wf() && perm.is_init(),
            RmemPerm::Shared(perm) => perm.wf() && perm.is_init(),
        }
    }

    /// The byte contents of the slice behind this capability.
    pub open spec fn view(self) -> Seq<u8> {
        match self {
            RmemPerm::Mut(perm) => perm.value()@,
            RmemPerm::Shared(perm) => perm.value()@,
        }
    }

    /// Whether this is a mutable (writable) capability, as opposed to a shared
    /// (read-only) one.
    pub open spec fn is_mut(self) -> bool {
        self is Mut
    }

    /// The buried `&mut [u8]` reference behind a mutable capability.
    pub open spec fn mut_value(self) -> &'a mut [u8]
        recommends
            self is Mut,
    {
        self->Mut_0.value()
    }
}

} // verus!
