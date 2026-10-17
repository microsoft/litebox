// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Services in runner processes, as the [control channel](crate::control)
//! serves them.

pub mod optee;
pub mod program;

/// A request/reply service in runner processes. The protocol defines both
/// types, and how failures, including a dead process, show up in the reply.
pub trait Service {
    type Request;
    type Reply;

    fn call(&mut self, request: Self::Request) -> Self::Reply;
}
