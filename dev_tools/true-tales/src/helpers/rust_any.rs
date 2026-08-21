// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Runtime `TypeId` helpers connected to Verus type-tag specifications.
use std::any::{Any, TypeId};
use vstd::prelude::*;

verus! {

/// Trusted logical representation of Rust's concrete TypeId.
pub uninterp spec fn type_tag<T: 'static>() -> int;

#[verifier::external_type_specification]
#[verifier::external_body]
#[allow(dead_code)]
pub struct ExTypeId(TypeId);

/// Executable `TypeId` wrapper with a logical [`type_tag`] view.
///
/// This is the reusable runtime companion to [`type_tag`]: executable code can
/// store and compare concrete `TypeId`s, while specifications use `spec_tag`.
#[verifier::external_body]
#[derive(Copy, Clone)]
pub struct RuntimeTypeTag {
    id: TypeId,
}

impl RuntimeTypeTag {
    pub uninterp spec fn spec_tag(self) -> int;

    /// Construct the runtime tag for `T`.
    #[verifier::external_body]
    pub fn of<T: 'static>() -> (tag: Self)
        ensures
            tag.spec_tag() == type_tag::<T>(),
    {
        RuntimeTypeTag { id: TypeId::of::<T>() }
    }

    /// Check whether this runtime tag names `T`.
    #[verifier::external_body]
    pub fn matches<T: 'static>(&self) -> (matched: bool)
        ensures
            matched ==> self.spec_tag() == type_tag::<T>(),
    {
        self.id == TypeId::of::<T>()
    }

    /// Compare two runtime tags.
    #[verifier::external_body]
    pub fn same(&self, other: &Self) -> (same: bool)
        ensures
            same ==> self.spec_tag() == other.spec_tag(),
    {
        self.id == other.id
    }
}

/// Runtime-checked borrowed downcast of an erased object.
#[verifier::external_body]
pub struct RuntimeAnyRef<'a> {
    inner: &'a dyn Any,
}

impl<'a> RuntimeAnyRef<'a> {
    #[verifier::external_body]
    pub fn new<T: 'static>(value: &'a T) -> (boxed: Self) {
        RuntimeAnyRef { inner: value }
    }

    #[verifier::external_body]
    pub fn downcast<T: 'static>(&self) -> (out: Option<&'a T>) {
        self.inner.downcast_ref::<T>()
    }
}

} // verus!
