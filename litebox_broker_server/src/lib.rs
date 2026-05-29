// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Channel-neutral broker server loop for the split-broker proof of concept.
//!
//! This crate wires `litebox_broker_core` to any implementation of the neutral
//! server control-channel trait. Concrete channels live in separate crates such as
//! `litebox_broker_unix_socket`.

#![no_std]

#[cfg(test)]
extern crate std;

mod server;

pub use server::{
    BrokerServeError, CloseReason, ConnectionTermination, SUPPORTED_PROTOCOL_VERSION,
    serve_connection,
};
