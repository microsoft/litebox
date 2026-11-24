// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Unverified native payload type registrations, not behavioral guarantees.
//! Kept separate from the checked kind-level duplication specification.

use vstd::prelude::*;

verus! {

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
