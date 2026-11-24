// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Original socket-kind projection, not naming, connection, or rights policy.

use super::UnixSocketObject;
use crate::object::ObjectEntry;
use crate::{BrokerError, Result};
use vstd::prelude::*;

verus! {

pub(crate) open spec fn unix_socket_projection(
    entry: &ObjectEntry,
    result: Result<&UnixSocketObject>,
) -> bool {
    match entry {
        ObjectEntry::UnixSocket(socket) => result == Ok(socket),
        _ => result == Err(BrokerError::InvalidRights),
    }
}

pub closed spec fn unix_socket_projection_policy() -> bool {
    forall|entry: &ObjectEntry, result: Result<&UnixSocketObject>|
        #[trigger] ObjectEntry::as_unix_socket.ensures((entry,), result)
            ==> unix_socket_projection(entry, result)
}

pub proof fn prove_unix_socket_projection()
    ensures unix_socket_projection_policy(),
{
}

}
