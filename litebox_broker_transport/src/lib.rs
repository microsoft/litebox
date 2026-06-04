// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker transport implementations.
//!
//! Transports own hosted or platform-specific framing and I/O. Portable broker
//! protocol messages, local-side adapters, host-side request handling, and core
//! authority state live in separate crates.

pub mod unix_socket;
