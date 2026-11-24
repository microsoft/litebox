// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! In progress: weak references are opaque values in scalar channel framing.
//! No allocation, reference-count, identity, upgrade, or liveness contract.

use alloc::alloc::Allocator;
use alloc::sync::Weak;
use vstd::prelude::*;

verus! {

#[verifier::external_type_specification]
#[verifier::external_body]
#[verifier::accept_recursive_types(T)]
#[verifier::reject_recursive_types(A)]
pub struct ExWeak<T: ?Sized, A: Allocator>(Weak<T, A>);

}
