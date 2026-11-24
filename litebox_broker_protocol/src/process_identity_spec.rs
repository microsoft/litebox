// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Original creator-ID conversions preserve numbers, not allocation validity,
//! uniqueness, namespace membership or authority.

use crate::{ProcessGroupId, ProcessId, SessionId};
use vstd::prelude::*;
use vstd::std_specs::convert::FromSpecImpl;

verus! {

impl FromSpecImpl<ProcessId> for ProcessGroupId {
    open spec fn obeys_from_spec() -> bool { true }
    open spec fn from_spec(creator: ProcessId) -> Self { ProcessGroupId(creator.0) }
}

impl FromSpecImpl<ProcessId> for SessionId {
    open spec fn obeys_from_spec() -> bool { true }
    open spec fn from_spec(creator: ProcessId) -> Self { SessionId(creator.0) }
}

pub closed spec fn process_identity_policy() -> bool {
    &&& forall|creator: ProcessId, result: ProcessGroupId|
        #[trigger] <ProcessGroupId as From<ProcessId>>::from.ensures((creator,), result)
            ==> result.0 == creator.0
    &&& forall|creator: ProcessId, result: SessionId|
        #[trigger] <SessionId as From<ProcessId>>::from.ensures((creator,), result)
            ==> result.0 == creator.0
}

pub proof fn prove_process_identity_conversions()
    ensures process_identity_policy(),
{
}

pub closed spec fn process_id_clone_policy() -> bool {
    forall|prev: ProcessId, cur: ProcessId|
        #[trigger] ProcessId::clone.ensures((&prev,), cur) ==> cur == prev
}

pub proof fn prove_process_id_clone()
    ensures process_id_clone_policy(),
{
}

}
