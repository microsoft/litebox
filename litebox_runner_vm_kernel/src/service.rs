// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Services in runner processes, as clients see them.

pub mod optee;

/// A request/reply service in runner processes; clients reach it only through
/// [`Service::call`]. The protocol defines both types, and how failures,
/// including a dead process, show up in the reply.
pub trait Service {
    type Request;
    type Reply;

    fn call(&mut self, request: Self::Request) -> Self::Reply;
}
