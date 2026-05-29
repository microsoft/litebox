// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Transport-neutral broker server loop for the split-broker proof of concept.
//!
//! This crate wires `litebox_broker_core` to any implementation of the neutral
//! server transport trait. Concrete transports live in separate crates such as
//! `litebox_broker_unix_socket`.

#![no_std]

mod server;

pub use server::{
    BrokerServeError, CloseReason, ConnectionTermination, SUPPORTED_PROTOCOL_VERSION,
    serve_connection,
};
