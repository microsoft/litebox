// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#[cfg(verus_only)]
use crate::fmem::erasure::ErasedArc;
#[cfg(verus_only)]
use crate::fmem::ids::{ForeignDomainId, ForeignRegionId};
use crate::fmem::ptr::ForeignPtr;
use crate::helpers::erased_pptr::ErasedPPtr;
use vstd::prelude::*;

verus! {

/// A "cursor" into some Rust slice.
#[derive(Copy, Clone)]
pub struct RustSliceCursor {
    pub slice_pptr: ErasedPPtr,
    pub offset: usize,
}

impl RustSliceCursor {
    pub open spec fn slice_pptr(self) -> ErasedPPtr {
        self.slice_pptr
    }

    pub open spec fn slice_addr(self) -> usize {
        self.slice_pptr.addr()
    }

    pub open spec fn slice_offset(self) -> usize {
        self.offset
    }
}

/// Executable register value.
#[derive(Copy, Clone)]
pub enum RegVal {
    /// A plain integer; the value is meaningful.
    Int(u64),
    /// A cursor into an injected shared (`&[u8]`) Rust slice, plus the
    /// current byte offset.
    RustSharedSlicePtr(RustSliceCursor),
    /// A cursor into an injected mutable (`&mut [u8]`) Rust slice, plus the
    /// current byte offset.
    RustMutSlicePtr(RustSliceCursor),
    /// A foreign-memory pointer (domain id, region id, byte offset).
    ForeignMemPtr(ForeignPtr),
    /// Unknown or intentionally abstract contents.
    Unknown,
}

impl RegVal {
    pub open spec fn is_int(self) -> bool {
        self is Int
    }

    pub open spec fn is_rust_shared_slice_ptr(self) -> bool {
        self is RustSharedSlicePtr
    }

    pub open spec fn is_rust_mut_slice_ptr(self) -> bool {
        self is RustMutSlicePtr
    }

    /// Whether this value is any Rust-slice cursor — mutable or shared.
    pub open spec fn is_slice_ptr(self) -> bool {
        self is RustMutSlicePtr || self is RustSharedSlicePtr
    }

    pub open spec fn is_foreign(self) -> bool {
        self is ForeignMemPtr
    }

    /// The integer a `RegVal::Int` holds (meaningless for other variants).
    pub open spec fn as_int(self) -> u64 {
        match self {
            RegVal::Int(v) => v,
            _ => 0,
        }
    }

    pub open spec fn slice_cursor(self) -> RustSliceCursor
        recommends
            self.is_slice_ptr(),
    {
        match self {
            RegVal::RustMutSlicePtr(rsc) => rsc,
            RegVal::RustSharedSlicePtr(rsc) => rsc,
            _ => arbitrary(),
        }
    }

    /// The type-erased privileged pointer a Rust-slice cursor holds.
    pub open spec fn slice_pptr(self) -> ErasedPPtr {
        match self {
            RegVal::RustMutSlicePtr(rsc) => rsc.slice_pptr,
            RegVal::RustSharedSlicePtr(rsc) => rsc.slice_pptr,
            _ => arbitrary(),
        }
    }

    /// The slice capability address a Rust-slice cursor holds.
    pub open spec fn slice_addr(self) -> usize {
        match self {
            RegVal::RustMutSlicePtr(rsc) => rsc.slice_addr(),
            RegVal::RustSharedSlicePtr(rsc) => rsc.slice_addr(),
            _ => 0,
        }
    }

    /// The byte offset a Rust-slice cursor holds.
    pub open spec fn slice_offset(self) -> usize {
        match self {
            RegVal::RustMutSlicePtr(rsc) => rsc.slice_offset(),
            RegVal::RustSharedSlicePtr(rsc) => rsc.slice_offset(),
            _ => 0,
        }
    }

    /// The foreign pointer a `RegVal::ForeignMemPtr` holds.
    pub open spec fn foreign_ptr(self) -> ForeignPtr
        recommends
            self.is_foreign(),
    {
        match self {
            RegVal::ForeignMemPtr(fmc) => fmc,
            _ => arbitrary(),
        }
    }

    /// The foreign-memory domain a foreign cursor holds.
    pub open spec fn foreign_domain(self) -> ForeignDomainId {
        match self {
            RegVal::ForeignMemPtr(fmc) => fmc.domain(),
            _ => arbitrary(),
        }
    }

    /// The foreign-memory region a foreign cursor holds.
    pub open spec fn foreign_region(self) -> ForeignRegionId {
        match self {
            RegVal::ForeignMemPtr(fmc) => fmc.region(),
            _ => ForeignRegionId { raw: 0 },
        }
    }

    /// The ghost capability a foreign cursor holds.
    pub open spec fn foreign_cap(self) -> ErasedArc {
        match self {
            RegVal::ForeignMemPtr(fmc) => fmc.cap(),
            _ => arbitrary(),
        }
    }

    /// The numeric address of the foreign cursor.
    pub open spec fn foreign_offset(self) -> usize {
        match self {
            RegVal::ForeignMemPtr(fmc) => fmc.cursor().addr(),
            _ => 0,
        }
    }

    pub fn int(value: u64) -> (v: Self)
        ensures
            v == RegVal::Int(value),
    {
        RegVal::Int(value)
    }

    pub fn unknown() -> (v: Self)
        ensures
            v == RegVal::Unknown,
    {
        RegVal::Unknown
    }

    pub fn rust_shared_slice_ptr(slice_pptr: ErasedPPtr, offset: usize) -> (v: Self)
        ensures
            v == RegVal::RustSharedSlicePtr(RustSliceCursor { slice_pptr, offset }),
    {
        RegVal::RustSharedSlicePtr(RustSliceCursor { slice_pptr, offset })
    }

    pub fn rust_mut_slice_ptr(slice_pptr: ErasedPPtr, offset: usize) -> (v: Self)
        ensures
            v == RegVal::RustMutSlicePtr(RustSliceCursor { slice_pptr, offset }),
    {
        RegVal::RustMutSlicePtr(RustSliceCursor { slice_pptr, offset })
    }

    pub fn foreign_mem_ptr(ptr: ForeignPtr) -> (v: Self)
        ensures
            v == RegVal::ForeignMemPtr(ptr),
    {
        RegVal::ForeignMemPtr(ptr)
    }

    /// Extract the integer from a `RegVal::Int`.
    pub fn unwrap_int(self) -> (v: u64)
        requires
            self is Int,
        ensures
            v == self.as_int(),
    {
        match self {
            RegVal::Int(v) => v,
            _ => vstd::pervasive::unreached(),
        }
    }

    /// Extract the slice cursor pointer and offset from a
    /// `RegVal::RustSharedSlicePtr` or `RegVal::RustMutSlicePtr`.
    pub fn unwrap_rust_slice_ptr(self) -> (res: (ErasedPPtr, usize))
        requires
            self is RustSharedSlicePtr || self is RustMutSlicePtr,
        ensures
            res.0 == self.slice_cursor().slice_pptr,
            res.0.addr() == self.slice_cursor().slice_addr(),
            res.1 == self.slice_cursor().slice_offset(),
    {
        match self {
            RegVal::RustSharedSlicePtr(RustSliceCursor { slice_pptr, offset }) => (
                slice_pptr,
                offset,
            ),
            RegVal::RustMutSlicePtr(RustSliceCursor { slice_pptr, offset }) => (slice_pptr, offset),
            _ => vstd::pervasive::unreached(),
        }
    }
}

} // verus!
