// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Opaque spin types used by the annotated broker object declarations.
//! Lock operations and their safety/behavior remain unverified.

use vstd::prelude::*;

verus! {

#[verifier::external_type_specification]
#[verifier::external_body]
pub struct ExSpin(spin::Spin);

#[verifier::external_type_specification]
#[verifier::external_body]
#[verifier::accept_recursive_types(T)]
#[verifier::reject_recursive_types(R)]
pub struct ExRwLock<T: ?Sized, R>(spin::rwlock::RwLock<T, R>);

}
