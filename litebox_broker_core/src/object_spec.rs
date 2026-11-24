// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Kind-level duplication policy for the original `ObjectEntry::is_duplicable`.
//! This proves neither caller rights nor policy/provenance checks at transfer.
//! Payloads are in progress and opaque: only the original enum's kind is used.

use super::ObjectEntry;
use vstd::prelude::*;

verus! {

pub open spec fn permitted_by_kind(entry: &ObjectEntry) -> bool {
    ||| entry is Event
    ||| entry is File
    ||| entry is UnixSocket
    ||| entry is Pipe
    ||| entry is Socket
    ||| entry is VsockSocket
    ||| entry is Timer
    ||| entry is ReadinessQueue
    ||| entry is Process
}

pub closed spec fn duplication_policy() -> bool {
    forall|entry: &ObjectEntry, result: bool|
        ObjectEntry::is_duplicable.ensures((entry,), result)
            ==> result == permitted_by_kind(entry)
}

pub proof fn prove_duplication_policy()
    ensures duplication_policy(),
{
}

// In progress: these payload implementations are outside the kind-only proof.
#[verifier::external_type_specification]
#[verifier::external_body]
pub struct ExEventObject(crate::event::EventObject);

#[verifier::external_type_specification]
#[verifier::external_body]
pub struct ExFile(crate::fs::File);

#[verifier::external_type_specification]
#[verifier::external_body]
pub struct ExUnixSocketObject(crate::unix_socket::UnixSocketObject);

#[verifier::external_type_specification]
#[verifier::external_body]
pub struct ExPipeObject(crate::pipe::PipeObject);

#[verifier::external_type_specification]
#[verifier::external_body]
pub struct ExSocketObject(crate::socket::SocketObject);

#[verifier::external_type_specification]
#[verifier::external_body]
pub struct ExVsockSocketObject(crate::vsock_socket::VsockSocketObject);

#[verifier::external_type_specification]
#[verifier::external_body]
pub struct ExSignalsObject(crate::signal::SignalsObject);

#[verifier::external_type_specification]
#[verifier::external_body]
pub struct ExTimerObject(crate::timer::TimerObject);

#[verifier::external_type_specification]
#[verifier::external_body]
pub struct ExReadinessQueueObject(crate::readiness_queue::ReadinessQueueObject);

#[verifier::external_type_specification]
#[verifier::external_body]
pub struct ExFutexWaiterObject(crate::shared_futex::FutexWaiterObject);

#[verifier::external_type_specification]
#[verifier::external_body]
pub struct ExProcessObject(crate::process::ProcessObject);

#[verifier::external_type_specification]
#[verifier::external_body]
pub struct ExObjectRights(crate::object::ObjectRights);

#[verifier::external_type_specification]
#[verifier::external_body]
pub struct ExReadinessRegistration(crate::readiness::ReadinessRegistration);

}
